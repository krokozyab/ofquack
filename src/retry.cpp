#include "ofquack/retry.hpp"

#include "ofquack/error_decoder.hpp"
#include "ofquack/errors.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>

namespace ofquack {

namespace {

bool ContainsIgnoringCase(const std::string &haystack, const std::string &needle) {
	if (needle.size() > haystack.size()) {
		return false;
	}
	const auto found = std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end(),
	                               [](char a, char b) {
		                               return std::tolower(static_cast<unsigned char>(a)) ==
		                                      std::tolower(static_cast<unsigned char>(b));
	                               });
	return found != haystack.end();
}

} // namespace

uint64_t ComputeBackoffDelay(const RetryPolicy &policy, uint32_t attempt,
                             const std::function<double()> &unit_random) {
	const auto exponential = static_cast<double>(policy.base_delay_ms) * std::pow(policy.multiplier, attempt);
	const auto capped = std::min(exponential, static_cast<double>(policy.max_delay_ms));

	// Jitter is applied after the cap, so the cap stays a real bound on the
	// expected wait rather than being exceeded by the random part.
	const auto spread = capped * policy.jitter;
	const auto offset = spread * (2.0 * unit_random() - 1.0);
	const auto delay = capped + offset;
	return delay <= 0.0 ? 0 : static_cast<uint64_t>(delay);
}

bool IsRetryableStatus(long status_code) {
	switch (status_code) {
	case 408: // request timeout
	case 429: // too many requests
	case 500: // BI Publisher reports transient internal failures this way
	case 502:
	case 503:
	case 504:
		return true;
	default:
		return false;
	}
}

bool IsRetryableCurlError(int curl_code) {
	// Values from curl.h, spelled numerically so this file needs no curl
	// header and stays testable without linking libcurl.
	switch (curl_code) {
	case 7:  // CURLE_COULDNT_CONNECT
	case 28: // CURLE_OPERATION_TIMEDOUT
	case 52: // CURLE_GOT_NOTHING
	case 55: // CURLE_SEND_ERROR
	case 56: // CURLE_RECV_ERROR
		return true;
	default:
		// Notably not retried: CURLE_COULDNT_RESOLVE_HOST (6), which is a
		// configuration mistake, and every TLS failure, which will repeat.
		return false;
	}
}

std::string ExecuteWithRetry(const RetryPolicy &policy, const std::function<std::string()> &attempt,
                             const std::function<void(uint64_t)> &sleep_ms,
                             const std::function<double()> &unit_random) {
	const auto attempts = policy.max_attempts == 0 ? 1 : policy.max_attempts;
	for (uint32_t attempt_index = 0;; attempt_index++) {
		try {
			return attempt();
		} catch (const RetryableError &retryable) {
			if (attempt_index + 1 >= attempts) {
				throw RetryableError(std::string(retryable.what()) + " (gave up after " + std::to_string(attempts) +
				                     (attempts == 1 ? " attempt)" : " attempts)"));
			}
			sleep_ms(ComputeBackoffDelay(policy, attempt_index, unit_random));
		}
	}
}

bool DescribesPermanentFailure(const std::string &response_text) {
	// An ORA- code means Oracle understood the request and refused it.
	if (!ExtractOracleErrors(response_text).empty()) {
		return true;
	}
	for (const auto *phrase : {"Oracle SQL error", "authentication failed", "invalid username or password",
	                           "Invalid credentials"}) {
		if (ContainsIgnoringCase(response_text, phrase)) {
			return true;
		}
	}
	return false;
}

} // namespace ofquack
