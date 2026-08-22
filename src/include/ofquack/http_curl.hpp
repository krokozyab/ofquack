#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace ofquack {

struct HttpRequest {
	std::string url;
	std::string body;
	std::vector<std::string> headers; //!< each entry is a full "Name: value" line
	uint64_t connect_timeout_seconds = 30;
	uint64_t read_timeout_seconds = 120;
	//! Polled while the transfer runs; returning true aborts it. May be empty.
	std::function<bool()> is_cancelled;
};

struct HttpResponse {
	long status_code = 0;
	std::string body;
	//! Value of WWW-Authenticate, when the server sent one. Used to tell a
	//! rejected password from an expired token.
	std::string www_authenticate;
	//! Value of Location on a redirect. Redirects are not followed -- a SOAP
	//! POST redirected to a sign-in page is an authentication problem, not a
	//! route to the answer -- but the target says which page it was.
	std::string location;
};

//! Holds one libcurl handle plus its cookie jar.
//!
//! Reusing the handle across requests keeps the BI Publisher session cookie, so
//! consecutive pages of one result do not each pay for a fresh server-side
//! session. Not thread safe: callers hold a HostThrottle slot, which serialises
//! use anyway.
class HttpClient {
public:
	HttpClient();
	~HttpClient();
	HttpClient(const HttpClient &) = delete;
	HttpClient &operator=(const HttpClient &) = delete;

	//! Performs one POST. Throws RetryableError or PermanentError for transport
	//! failures; an HTTP error *status* is returned rather than thrown, so the
	//! caller can classify it against the response body.
	HttpResponse Post(const HttpRequest &request);

	//! Performs one GET. Used for the browser's debugging endpoint, which is
	//! plain HTTP on loopback.
	HttpResponse Get(const HttpRequest &request);

private:
	HttpResponse Perform(const HttpRequest &request, bool post);

	struct Impl;
	std::unique_ptr<Impl> impl;
};

} // namespace ofquack
