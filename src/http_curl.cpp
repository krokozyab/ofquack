#include "ofquack/http_curl.hpp"

#include "ofquack/errors.hpp"
#include "ofquack/retry.hpp"

#include <algorithm>
#include <cctype>
#include <curl/curl.h>

namespace ofquack {

namespace {

size_t AppendToString(void *contents, size_t size, size_t nmemb, void *userp) {
	auto &out = *static_cast<std::string *>(userp);
	const size_t byte_count = size * nmemb;
	out.append(static_cast<char *>(contents), byte_count);
	return byte_count;
}

//! Captures WWW-Authenticate, which is what separates "wrong password" from
//! "expired token" on a 401.
size_t CollectHeader(char *buffer, size_t size, size_t nitems, void *userp) {
	auto &response = *static_cast<HttpResponse *>(userp);
	const size_t byte_count = size * nitems;
	const std::string line(buffer, byte_count);

	static const std::string NAME = "www-authenticate:";
	if (line.size() > NAME.size()) {
		std::string lowered = line.substr(0, NAME.size());
		std::transform(lowered.begin(), lowered.end(), lowered.begin(),
		               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
		if (lowered == NAME) {
			auto value = line.substr(NAME.size());
			const auto first = value.find_first_not_of(" \t");
			const auto last = value.find_last_not_of(" \t\r\n");
			response.www_authenticate =
			    first == std::string::npos ? std::string() : value.substr(first, last - first + 1);
		}
	}
	return byte_count;
}

int ReportProgress(void *userp, curl_off_t, curl_off_t, curl_off_t, curl_off_t) {
	const auto &is_cancelled = *static_cast<const std::function<bool()> *>(userp);
	// A non-zero return aborts the transfer with CURLE_ABORTED_BY_CALLBACK.
	return is_cancelled && is_cancelled() ? 1 : 0;
}

struct HeaderList {
	curl_slist *list = nullptr;

	~HeaderList() {
		curl_slist_free_all(list);
	}
	void Append(const std::string &header) {
		list = curl_slist_append(list, header.c_str());
	}
};

} // namespace

struct HttpClient::Impl {
	CURL *handle = nullptr;

	Impl() {
		handle = curl_easy_init();
		if (!handle) {
			throw PermanentError("Failed to initialise libcurl");
		}
		// An empty cookie file enables the in-memory cookie engine: nothing is
		// read from or written to disk, but cookies set by the server are kept
		// for the life of this handle. That is what preserves the BI Publisher
		// session between the pages of one result.
		curl_easy_setopt(handle, CURLOPT_COOKIEFILE, "");
		// libcurl advertises what it can decode and inflates the body itself.
		curl_easy_setopt(handle, CURLOPT_ACCEPT_ENCODING, "");
	}

	~Impl() {
		if (handle) {
			curl_easy_cleanup(handle);
		}
	}
};

HttpClient::HttpClient() : impl(new Impl()) {
}

HttpClient::~HttpClient() = default;

HttpResponse HttpClient::Get(const HttpRequest &request) {
	return Perform(request, false);
}

HttpResponse HttpClient::Post(const HttpRequest &request) {
	return Perform(request, true);
}

HttpResponse HttpClient::Perform(const HttpRequest &request, bool post) {
	auto *handle = impl->handle;
	curl_easy_reset(handle);
	// Reset clears the transfer options but keeps the cookie jar with the handle.
	curl_easy_setopt(handle, CURLOPT_COOKIEFILE, "");
	curl_easy_setopt(handle, CURLOPT_ACCEPT_ENCODING, "");

	HeaderList headers;
	for (const auto &header : request.headers) {
		headers.Append(header);
	}

	HttpResponse response;
	curl_easy_setopt(handle, CURLOPT_URL, request.url.c_str());
	curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers.list);
	if (post) {
		curl_easy_setopt(handle, CURLOPT_POST, 1L);
		curl_easy_setopt(handle, CURLOPT_POSTFIELDS, request.body.c_str());
		curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, static_cast<long>(request.body.size()));
	} else {
		curl_easy_setopt(handle, CURLOPT_HTTPGET, 1L);
	}
	curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, AppendToString);
	curl_easy_setopt(handle, CURLOPT_WRITEDATA, &response.body);
	curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, CollectHeader);
	curl_easy_setopt(handle, CURLOPT_HEADERDATA, &response);
	curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, static_cast<long>(request.connect_timeout_seconds));
	curl_easy_setopt(handle, CURLOPT_TIMEOUT, static_cast<long>(request.read_timeout_seconds));
	curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 0L);

	if (request.is_cancelled) {
		curl_easy_setopt(handle, CURLOPT_NOPROGRESS, 0L);
		curl_easy_setopt(handle, CURLOPT_XFERINFOFUNCTION, ReportProgress);
		curl_easy_setopt(handle, CURLOPT_XFERINFODATA, &request.is_cancelled);
	}

	const CURLcode code = curl_easy_perform(handle);
	if (code == CURLE_ABORTED_BY_CALLBACK) {
		throw CancelledError("The Oracle Fusion request was cancelled");
	}
	if (code != CURLE_OK) {
		const std::string message =
		    std::string("Oracle Fusion request failed: ") + curl_easy_strerror(code) + " (" + request.url + ")";
		if (IsRetryableCurlError(static_cast<int>(code))) {
			throw RetryableError(message);
		}
		throw PermanentError(message);
	}
	curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &response.status_code);
	return response;
}

} // namespace ofquack
