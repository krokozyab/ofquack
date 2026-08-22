#include "ofquack/soap_transport.hpp"

#include "base64.h"
#include "ofquack/http_curl.hpp"
#include "ofquack/soap_envelope.hpp"

#include <stdexcept>

namespace ofquack {

namespace {

class SoapTransport : public FusionTransport {
public:
	explicit SoapTransport(FusionConfig config_p) : config(std::move(config_p)) {
	}

	std::string Execute(const std::string &sql, const RequestContext &context) override {
		(void)context; // cancellation and deadlines arrive with the retry layer

		const std::string credentials = config.username + ":" + config.password;
		HttpRequest request;
		request.url = config.endpoint;
		request.body = BuildEnvelope(sql, config.report_path);
		request.headers = {
		    "Content-Type: application/soap+xml;charset=UTF-8",
		    "SOAPAction: #POST",
		    "Authorization: Basic " +
		        base64_encode(reinterpret_cast<const unsigned char *>(credentials.c_str()), credentials.size()),
		};

		auto response = HttpPost(request);
		// A login redirect or a gateway error page arrives as HTML where XML was
		// expected; saying so beats a parser error 200 lines later.
		if (response.body.rfind("<html", 0) == 0) {
			throw std::runtime_error("Received HTML error page");
		}
		return response.body;
	}

private:
	FusionConfig config;
};

} // namespace

std::shared_ptr<FusionTransport> CreateSoapTransport(const FusionConfig &config) {
	return std::make_shared<SoapTransport>(config);
}

} // namespace ofquack
