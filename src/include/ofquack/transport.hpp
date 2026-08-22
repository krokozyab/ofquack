#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace ofquack {

enum class AuthMode {
	BASIC,  //!< username and password
	BEARER, //!< a token, from the cache or supplied directly
};

//! Everything needed to reach one Fusion instance's BI Publisher report.
//!
//! The resilience defaults match the JDBC driver's, so both clients put the
//! same load on an instance.
struct FusionConfig {
	std::string endpoint;    //!< ExternalReportWSSService WSDL URL
	std::string username;
	std::string password;
	std::string report_path; //!< absolute path of the .xdo report, e.g. /Custom/Financials/RP_ARB.xdo

	AuthMode auth = AuthMode::BASIC;
	//! Seed token for AuthMode::BEARER. The token cache takes over once it
	//! holds anything fresher, so this is a starting point, not the truth.
	std::string token;

	uint64_t connect_timeout_seconds = 30;
	uint64_t read_timeout_seconds = 120;
	uint32_t max_attempts = 3;
	uint64_t retry_base_ms = 1000;
	uint64_t retry_max_ms = 30000;
	uint32_t breaker_threshold = 5;
	uint64_t breaker_recovery_ms = 60000;
	//! One at a time by default: each request opens a BI Publisher session that
	//! the server holds on to.
	uint32_t max_concurrent_requests = 1;
};

//! Per-request cancellation and deadline. Both are optional.
struct RequestContext {
	std::function<bool()> is_cancelled; //!< empty means "never cancelled"
	int64_t deadline_epoch_ms = 0;      //!< 0 means "no deadline"

	//! Shared no-op context, for call sites with nothing to cancel.
	static const RequestContext &None();
};

//! The seam between talking to Fusion and making sense of what comes back.
//!
//! Every caller above this interface goes through it, so the entire query,
//! metadata and catalog layer can be tested against scripted responses without
//! a Fusion instance or a network.
class FusionTransport {
public:
	virtual ~FusionTransport() = default;

	//! Runs one SQL statement through BI Publisher and returns the raw SOAP
	//! response body. Throws on transport failure.
	virtual std::string Execute(const std::string &sql, const RequestContext &context) = 0;

	//! Drops the connection and its session cookie, so the next request starts
	//! a fresh BI Publisher session.
	//!
	//! Reusing one session across a long listing is normally the right thing --
	//! it saves the server the cost of establishing one per page. But a session
	//! appears to accumulate some allowance, after which pages come back empty
	//! rather than failing, which is indistinguishable from having reached the
	//! end of the data. Starting over is how that is told apart.
	virtual void ResetSession() {
	}
};

using TransportFactory = std::function<std::shared_ptr<FusionTransport>(const FusionConfig &)>;

//! Builds the transport currently in effect: the real SOAP one, unless a
//! ScopedTransportFactory is active.
std::shared_ptr<FusionTransport> CreateTransport(const FusionConfig &config);

//! Installs a transport factory for as long as it is in scope. Test-only;
//! not thread safe by design, since tests install it before doing any work.
class ScopedTransportFactory {
public:
	explicit ScopedTransportFactory(TransportFactory factory);
	~ScopedTransportFactory();

	ScopedTransportFactory(const ScopedTransportFactory &) = delete;
	ScopedTransportFactory &operator=(const ScopedTransportFactory &) = delete;

private:
	TransportFactory previous;
};

} // namespace ofquack
