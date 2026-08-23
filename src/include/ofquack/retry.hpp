#pragma once

#include <cstdint>
#include <functional>
#include <string>

namespace ofquack {

//! Exponential backoff with jitter, matching the JDBC driver's defaults so both
//! clients put the same load on a Fusion instance.
struct RetryPolicy {
	uint32_t max_attempts = 3;
	uint64_t base_delay_ms = 1000;
	uint64_t max_delay_ms = 30000;
	double multiplier = 2.0;
	//! Fraction of the delay to spread randomly either way. Without it, a set
	//! of clients that failed together retries together, forever.
	double jitter = 0.2;
};

//! Delay before attempt number `attempt` (0 is the first retry).
//!
//! `unit_random` returns a value in [0, 1); it is a parameter rather than a
//! call to a global generator so the tests are deterministic.
uint64_t ComputeBackoffDelay(const RetryPolicy &policy, uint32_t attempt,
                             const std::function<double()> &unit_random);

//! HTTP statuses worth another attempt: transient server and gateway failures,
//! request timeout, and rate limiting.
bool IsRetryableStatus(int64_t status_code);

//! True if this libcurl error code describes a transport failure rather than a
//! refusal by the server.
bool IsRetryableCurlError(int curl_code);

//! True when the response text names a failure that will not go away: an
//! Oracle error code, or a rejected login. Retrying such a response wastes the
//! user's time and, for a bad password, risks locking the account.
bool DescribesPermanentFailure(const std::string &response_text);

//! Runs `attempt` until it succeeds, until it fails permanently, or until the
//! policy runs out of attempts.
//!
//! Only RetryableError is retried; everything else propagates immediately.
//! `sleep_ms` and `unit_random` are parameters rather than direct calls so the
//! whole loop can be tested without waiting and without randomness.
std::string ExecuteWithRetry(const RetryPolicy &policy, const std::function<std::string()> &attempt,
                             const std::function<void(uint64_t)> &sleep_ms,
                             const std::function<double()> &unit_random);

} // namespace ofquack
