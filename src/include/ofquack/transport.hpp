#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace ofquack {

//! Everything needed to reach one Fusion instance's BI Publisher report.
struct FusionConfig {
	std::string endpoint;    //!< ExternalReportWSSService WSDL URL
	std::string username;
	std::string password;
	std::string report_path; //!< absolute path of the .xdo report, e.g. /Custom/Financials/RP_ARB.xdo
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
