#include "ofquack/soap_transport.hpp"

#include "base64.h"
#include "ofquack/circuit_breaker.hpp"
#include "ofquack/error_decoder.hpp"
#include "ofquack/errors.hpp"
#include "ofquack/host_throttle.hpp"
#include "ofquack/http_curl.hpp"
#include "ofquack/retry.hpp"
#include "ofquack/soap_envelope.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
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

class SoapTransport : public FusionTransport {
public:
	explicit SoapTransport(FusionConfig config_p)
	    : config(std::move(config_p)), host(HostOf(config.endpoint)),
	      throttle(ThrottleForHost(host, config.max_concurrent_requests)),
	      breaker(BreakerForHost(host, CircuitBreakerSettings {config.breaker_threshold, config.breaker_recovery_ms})),
	      random_engine(std::random_device {}()) {
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
	std::string Attempt(const std::string &sql, const RequestContext &context) {
		breaker->RequireClosed(host);
		// Held for the whole request: the point is to bound how many BI
		// Publisher sessions exist at once, not how many we start per second.
		HostThrottle::Slot slot(*throttle);

		const std::string credentials = config.username + ":" + config.password;
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
		    "Authorization: Basic " +
		        base64_encode(reinterpret_cast<const unsigned char *>(credentials.c_str()), credentials.size()),
		};

		HttpResponse response;
		try {
			response = client.Post(request);
		} catch (const FusionError &) {
			breaker->RecordFailure();
			throw;
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
	HttpClient client;
	std::mt19937 random_engine;
};

} // namespace

std::shared_ptr<FusionTransport> CreateSoapTransport(const FusionConfig &config) {
	return std::make_shared<SoapTransport>(config);
}

} // namespace ofquack
