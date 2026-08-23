#include "ofquack/soap_transport.hpp"

#include "base64.h"
#include "ofquack/circuit_breaker.hpp"
#include "ofquack/error_decoder.hpp"
#include "ofquack/errors.hpp"
#include "ofquack/host_throttle.hpp"
#include "ofquack/http_curl.hpp"
#include "ofquack/retry.hpp"
#include "ofquack/soap_envelope.hpp"
#include "ofquack/token_cache.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <memory>
#include <random>
#include <thread>

namespace ofquack {

namespace {

bool StartsWithIgnoringCase(const std::string &text, const std::string &prefix) {
	if (text.size() < prefix.size()) {
		return false;
	}
	for (size_t i = 0; i < prefix.size(); i++) {
		if (std::tolower(static_cast<unsigned char>(text[i])) != std::tolower(static_cast<unsigned char>(prefix[i]))) {
			return false;
		}
	}
	return true;
}

int64_t NowEpochMs() {
	return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

void ThrowIfCancelled(const RequestContext &context) {
	if (context.is_cancelled && context.is_cancelled()) {
		throw CancelledError("The Oracle Fusion request was cancelled");
	}
	if (context.deadline_epoch_ms != 0 && NowEpochMs() >= context.deadline_epoch_ms) {
		throw CancelledError("The Oracle Fusion request exceeded its deadline");
	}
}

//! Sleeps in short steps so a cancellation is noticed during the backoff rather
//! than only after it. A 30 second wait that ignores Ctrl-C is its own bug.
void SleepRespectingCancellation(uint64_t delay_ms, const RequestContext &context) {
	constexpr uint64_t STEP_MS = 100;
	for (uint64_t slept = 0; slept < delay_ms; slept += STEP_MS) {
		ThrowIfCancelled(context);
		std::this_thread::sleep_for(std::chrono::milliseconds(std::min(STEP_MS, delay_ms - slept)));
	}
}

//! Turns an HTTP error status into the right kind of exception.
//!
//! The 401 split matters: a rejected password must never be retried, because
//! repeating it can lock the account, while an expired bearer token is worth
//! one more attempt after a refresh. Fusion also reports a JWT that lacks the
//! SOAP privilege as a 500 with a specific message rather than as a 401.
[[noreturn]] void ThrowForStatus(const HttpResponse &response, const std::string &url) {
	const auto described = DescribeFailure(response.body);
	const auto suffix = described.empty() ? std::string() : ": " + described;

	if (response.status_code == 401 || response.status_code == 403) {
		if (StartsWithIgnoringCase(response.www_authenticate, "Bearer")) {
			throw TokenExpiredError("Oracle Fusion rejected the bearer token" + suffix);
		}
		throw AuthenticationError("Oracle Fusion rejected the credentials (HTTP " +
		                          std::to_string(response.status_code) + ")" + suffix +
		                          ". Check the username and password on the secret");
	}
	if (response.status_code == 500 &&
	    response.body.find("Access denied. Check \"Access SOAP\" privilege") != std::string::npos) {
		throw TokenExpiredError("The Oracle Fusion token lacks the Access SOAP privilege" + suffix);
	}
	if (DescribesPermanentFailure(response.body)) {
		throw PermanentError("Oracle Fusion rejected the request" + suffix);
	}
	const auto message = "Oracle Fusion returned HTTP " + std::to_string(response.status_code) + " for " + url + suffix;
	if (IsRetryableStatus(response.status_code)) {
		throw RetryableError(message);
	}
	throw PermanentError(message);
}

//! True when a redirect target looks like an authentication step rather than a
//! page of the application.
bool LooksLikeSignIn(const std::string &location) {
	static const char *const MARKERS[] = {"/oam/",     "/oamsso", "login",  "signin",
	                                      "sign-in",   "/sso",    "/adfs/", "/saml"};
	auto lowered = location;
	std::transform(lowered.begin(), lowered.end(), lowered.begin(),
	               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	for (const auto *marker : MARKERS) {
		if (lowered.find(marker) != std::string::npos) {
			return true;
		}
	}
	return false;
}

//! Explains a redirect, which is never a route to the answer.
//!
//! The two shapes mean different things and must not be reported alike. A
//! redirect to a sign-in page is an authentication failure. A redirect to a
//! page of the application -- Fusion's home page, typically -- means the
//! request was accepted as browser navigation rather than as a SOAP call, and
//! points at the endpoint or at the account's access to BI Publisher, not at
//! the credentials.
[[noreturn]] void RedirectedAway(const HttpResponse &response, const std::string &endpoint, AuthMode auth) {
	const auto target = response.location.empty() ? std::string("an unnamed page") : response.location;

	if (!response.location.empty() && !LooksLikeSignIn(response.location)) {
		throw PermanentError(
		    "Oracle Fusion redirected the SOAP request to " + target +
		    ", which is a page of the application rather than a sign-in page.\n"
		    "The request reached the server but was not treated as a web service call. Check that ENDPOINT "
		    "points at the BI Publisher service -- it should end in "
		    "/xmlpserver/services/ExternalReportWSSService?WSDL -- and that the account has the Access SOAP "
		    "privilege and can open BI Publisher.\nEndpoint used: " +
		    endpoint);
	}

	if (auth == AuthMode::BEARER) {
		throw TokenExpiredError("Oracle Fusion redirected the request to a sign-in page (" + target +
		                        "), so the token was not accepted. Sign in again with "
		                        "SELECT * FROM fusion_scanner_sso_login(force := true)");
	}
	throw AuthenticationError(
	    "Oracle Fusion redirected the request to a sign-in page (" + target +
	    ").\nThe credentials were not accepted, or this instance uses single sign-on -- in which case the "
	    "secret needs PROVIDER browser and SELECT * FROM fusion_scanner_sso_login().");
}

class SoapTransport : public FusionTransport {
public:
	explicit SoapTransport(FusionConfig config_p)
	    : config(std::move(config_p)), host(HostOf(config.endpoint)),
	      throttle(ThrottleForHost(host, config.max_concurrent_requests)),
	      breaker(BreakerForHost(host, CircuitBreakerSettings {config.breaker_threshold, config.breaker_recovery_ms})),
	      random_engine(std::random_device {}()) {
	}

	void ResetSession() override {
		HostThrottle::Slot slot(*throttle);
		client = std::make_unique<HttpClient>();
	}

	std::string Execute(const std::string &sql, const RequestContext &context) override {
		const RetryPolicy policy {config.max_attempts, config.retry_base_ms, config.retry_max_ms, 2.0, 0.2};

		return ExecuteWithRetry(
		    policy,
		    [&]() {
			    ThrowIfCancelled(context);
			    return Attempt(sql, context);
		    },
		    [&](uint64_t delay_ms) { SleepRespectingCancellation(delay_ms, context); },
		    [this]() {
			    std::uniform_real_distribution<double> distribution(0.0, 1.0);
			    return distribution(random_engine);
		    });
	}

private:
	//! Builds the Authorization header for this attempt.
	//!
	//! For bearer auth the live token is read fresh each time rather than being
	//! captured once: a long scan can outlive the token it started with, and
	//! the cache may have been refreshed by another query in the meantime.
	std::string AuthorizationHeader() {
		if (config.auth == AuthMode::BEARER) {
			auto cached = TokenCache::Get().Lookup(host);
			const auto token = cached.Valid() ? cached.access_token : config.token;
			if (token.empty()) {
				throw AuthenticationError(
				    "No Oracle Fusion token is available for " + host +
				    ". Run SELECT * FROM fusion_scanner_sso_login() to sign in, or set TOKEN on the secret");
			}
			return "Authorization: Bearer " + token;
		}
		const std::string credentials = config.username + ":" + config.password;
		return "Authorization: Basic " +
		       base64_encode(reinterpret_cast<const unsigned char *>(credentials.c_str()), credentials.size());
	}

	std::string Attempt(const std::string &sql, const RequestContext &context) {
		// Held for the whole request: the point is to bound how many BI
		// Publisher sessions exist at once, not how many we start per second.
		HostThrottle::Slot slot(*throttle);
		// Checked after the slot, not before. A queue of callers that all passed
		// the check while the breaker was closed would otherwise run one after
		// another into an instance that failed on the first of them.
		breaker->RequireClosed(host);

		HttpRequest request;
		request.url = config.endpoint;
		request.body = BuildEnvelope(sql, config.report_path);
		request.connect_timeout_seconds = config.connect_timeout_seconds;
		request.read_timeout_seconds = config.read_timeout_seconds;
		request.is_cancelled = context.is_cancelled;
		request.headers = {
		    "Content-Type: application/soap+xml;charset=UTF-8",
		    "SOAPAction: #POST",
		    "User-Agent: ofquack",
		    AuthorizationHeader(),
		};

		HttpResponse response;
		try {
			response = client->Post(request);
		} catch (const CancelledError &) {
			// The caller stopped, which says nothing about the instance. Counting
			// it would let a few interrupted queries close the breaker on a host
			// that was answering perfectly well.
			throw;
		} catch (const PermanentError &) {
			// Same rule as for a rejected status: a refusal is not a failure. A
			// bad CA file or an unusable proxy will not fix itself by waiting,
			// and tripping on it would block every other query to this host.
			throw;
		} catch (const FusionError &) {
			breaker->RecordFailure();
			throw;
		}

		// A redirect is not a route to the answer. Fusion answers an
		// unauthenticated request with one, pointing at the sign-in page, and
		// following it would fetch that page and hand it to the XML parser --
		// which is how this used to surface as "Missing SOAP Envelope",
		// several layers away from the actual problem.
		if (response.status_code >= 300 && response.status_code < 400) {
			RedirectedAway(response, config.endpoint, config.auth);
		}

		if (response.status_code >= 400) {
			// Not counted as a breaker failure when it is the caller's fault:
			// a bad password or a missing table says nothing about the health
			// of the instance, and tripping on it would block every other query.
			try {
				ThrowForStatus(response, config.endpoint);
			} catch (const PermanentError &) {
				throw;
			} catch (const FusionError &) {
				breaker->RecordFailure();
				throw;
			}
		}

		// A login redirect or a gateway page arrives as HTML where XML was
		// expected; saying so beats a parser error two hundred lines later.
		if (StartsWithIgnoringCase(response.body, "<html")) {
			const auto described = DescribeFailure(response.body);
			throw PermanentError("Oracle Fusion returned an HTML page instead of a SOAP response" +
			                     (described.empty() ? std::string() : ": " + described));
		}

		breaker->RecordSuccess();
		return response.body;
	}

	FusionConfig config;
	std::string host;
	std::shared_ptr<HostThrottle> throttle;
	std::shared_ptr<CircuitBreaker> breaker;
	std::unique_ptr<HttpClient> client = std::make_unique<HttpClient>();
	std::mt19937 random_engine;
};

} // namespace

std::shared_ptr<FusionTransport> CreateSoapTransport(const FusionConfig &config) {
	return std::make_shared<SoapTransport>(config);
}

} // namespace ofquack
