#pragma once

#include <chrono>
#include <functional>
#include <cstdint>
#include <mutex>
#include <string>

namespace ofquack {

struct CircuitBreakerSettings {
	//! Consecutive failures before the circuit opens.
	uint32_t failure_threshold = 5;
	//! How long to stay open before letting one probe through.
	uint64_t recovery_ms = 60000;
};

//! Stops hammering a Fusion instance that is already failing.
//!
//! Every request opens a BI Publisher session, which the server holds for a
//! while. Retrying into an instance that is down therefore does not just waste
//! the caller's time, it piles up sessions that make recovery slower. After
//! `failure_threshold` consecutive failures the breaker opens and requests fail
//! immediately; after `recovery_ms` a single probe is allowed through, and its
//! outcome either closes the breaker or opens it again.
class CircuitBreaker {
public:
	enum class State { CLOSED, OPEN, HALF_OPEN };

	explicit CircuitBreaker(CircuitBreakerSettings settings = {});

	//! Called before a request. Throws CircuitOpenError if it must not proceed.
	//! `host` only shapes the error message.
	void RequireClosed(const std::string &host);

	void RecordSuccess();
	void RecordFailure();

	State CurrentState() const;

	//! Test seam: lets a suite move time without sleeping.
	void SetClockForTesting(std::function<std::chrono::steady_clock::time_point()> clock);

private:
	State StateAtLocked(std::chrono::steady_clock::time_point now) const;

	CircuitBreakerSettings settings;
	mutable std::mutex lock;
	State state = State::CLOSED;
	uint32_t consecutive_failures = 0;
	std::chrono::steady_clock::time_point opened_at;
	std::function<std::chrono::steady_clock::time_point()> now_fn;
};

} // namespace ofquack
