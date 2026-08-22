#pragma once

#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

namespace ofquack {

//! Limits how many requests may be in flight against one Fusion host.
//!
//! The default is one. This is not caution about our own resources: every
//! runReport call opens a BI Publisher session that the server keeps for a
//! while, and a handful of parallel scans is enough to leave hundreds of them
//! behind -- the JDBC driver ships the same limit for the same reason.
class HostThrottle {
public:
	explicit HostThrottle(uint32_t max_concurrent);

	//! Blocks until a slot is free, then holds it until destroyed.
	class Slot {
	public:
		Slot(HostThrottle &owner_p);
		~Slot();
		Slot(const Slot &) = delete;
		Slot &operator=(const Slot &) = delete;

	private:
		HostThrottle &owner;
	};

private:
	friend class Slot;

	std::mutex lock;
	std::condition_variable slot_freed;
	uint32_t available;
};

class CircuitBreaker;
struct CircuitBreakerSettings;

//! Process-wide registry, keyed by host. Two connections to the same instance
//! share a limit, which is the point: the limit protects the server, not us.
std::shared_ptr<HostThrottle> ThrottleForHost(const std::string &host, uint32_t max_concurrent);

//! Likewise for the breaker: one failing instance should trip for every
//! connection that talks to it, not just the one that noticed.
std::shared_ptr<CircuitBreaker> BreakerForHost(const std::string &host, const CircuitBreakerSettings &settings);

//! Host part of a URL, used as the throttle and breaker key.
std::string HostOf(const std::string &url);

//! Test seam: drops every registered throttle and breaker.
void ResetHostStateForTesting();

} // namespace ofquack
