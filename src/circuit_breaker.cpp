#include "ofquack/circuit_breaker.hpp"

#include "ofquack/errors.hpp"

namespace ofquack {

CircuitBreaker::CircuitBreaker(CircuitBreakerSettings settings_p)
    : settings(settings_p), now_fn([]() { return std::chrono::steady_clock::now(); }) {
}

void CircuitBreaker::SetClockForTesting(std::function<std::chrono::steady_clock::time_point()> clock) {
	std::lock_guard<std::mutex> guard(lock);
	now_fn = std::move(clock);
}

CircuitBreaker::State CircuitBreaker::StateAtLocked(std::chrono::steady_clock::time_point now) const {
	if (state != State::OPEN) {
		return state;
	}
	const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - opened_at).count();
	if (elapsed >= static_cast<int64_t>(settings.recovery_ms)) {
		return State::HALF_OPEN;
	}
	return State::OPEN;
}

void CircuitBreaker::RequireClosed(const std::string &host) {
	std::lock_guard<std::mutex> guard(lock);
	const auto now = now_fn();
	const auto effective = StateAtLocked(now);
	if (effective == State::OPEN) {
		const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - opened_at).count();
		const auto remaining = static_cast<int64_t>(settings.recovery_ms) - elapsed;
		throw CircuitOpenError("Oracle Fusion at " + host + " has failed " +
		                       std::to_string(settings.failure_threshold) +
		                       " times in a row, so this request was not attempted. Retrying in " +
		                       std::to_string(remaining > 0 ? remaining / 1000 : 0) +
		                       "s. Check that the instance is reachable and that the report is deployed");
	}
	// A half-open breaker lets exactly one probe through; it stays half-open
	// until that probe reports back, so a burst of queries does not all rush in.
	state = effective;
}

void CircuitBreaker::RecordSuccess() {
	std::lock_guard<std::mutex> guard(lock);
	consecutive_failures = 0;
	state = State::CLOSED;
}

void CircuitBreaker::RecordFailure() {
	std::lock_guard<std::mutex> guard(lock);
	if (state == State::HALF_OPEN) {
		// The probe failed: the instance is still unwell, so wait again from now.
		state = State::OPEN;
		opened_at = now_fn();
		return;
	}
	consecutive_failures++;
	if (consecutive_failures >= settings.failure_threshold) {
		state = State::OPEN;
		opened_at = now_fn();
	}
}

CircuitBreaker::State CircuitBreaker::CurrentState() const {
	std::lock_guard<std::mutex> guard(lock);
	return StateAtLocked(now_fn());
}

} // namespace ofquack
