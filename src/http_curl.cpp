#include "ofquack/http_curl.hpp"

#include <curl/curl.h>
#include <stdexcept>

namespace ofquack {

namespace {

size_t AppendToString(void *contents, size_t size, size_t nmemb, void *userp) {
	auto &out = *static_cast<std::string *>(userp);
	const size_t byte_count = size * nmemb;
	out.append(static_cast<char *>(contents), byte_count);
	return byte_count;
}

//! Frees the header list even when the body of HttpPost throws.
struct HeaderList {
	curl_slist *list = nullptr;

	~HeaderList() {
		curl_slist_free_all(list);
	}
	void Append(const std::string &header) {
		list = curl_slist_append(list, header.c_str());
	}
};

struct EasyHandle {
	CURL *handle = curl_easy_init();

	~EasyHandle() {
		if (handle) {
			curl_easy_cleanup(handle);
		}
	}
};

} // namespace

HttpResponse HttpPost(const HttpRequest &request) {
	EasyHandle curl;
	if (!curl.handle) {
		throw std::runtime_error("Failed to init CURL");
	}

	HeaderList headers;
	for (const auto &header : request.headers) {
		headers.Append(header);
	}

	HttpResponse response;
	curl_easy_setopt(curl.handle, CURLOPT_URL, request.url.c_str());
	curl_easy_setopt(curl.handle, CURLOPT_HTTPHEADER, headers.list);
	curl_easy_setopt(curl.handle, CURLOPT_POSTFIELDS, request.body.c_str());
	curl_easy_setopt(curl.handle, CURLOPT_WRITEFUNCTION, AppendToString);
	curl_easy_setopt(curl.handle, CURLOPT_WRITEDATA, &response.body);

	const CURLcode code = curl_easy_perform(curl.handle);
	if (code != CURLE_OK) {
		throw std::runtime_error(std::string("SOAP request failed: ") + curl_easy_strerror(code));
	}
	curl_easy_getinfo(curl.handle, CURLINFO_RESPONSE_CODE, &response.status_code);
	return response;
}

} // namespace ofquack
