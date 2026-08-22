#pragma once

#include <string>
#include <vector>

namespace ofquack {

struct HttpRequest {
	std::string url;
	std::string body;
	std::vector<std::string> headers; //!< each entry is a full "Name: value" line
};

struct HttpResponse {
	long status_code = 0;
	std::string body;
};

//! Performs one HTTP POST and returns the response. Throws std::runtime_error
//! if the request could not be completed at all; an HTTP error *status* is
//! reported in the response rather than thrown, so callers can classify it.
HttpResponse HttpPost(const HttpRequest &request);

} // namespace ofquack
