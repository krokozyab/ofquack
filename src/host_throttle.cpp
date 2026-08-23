#include "ofquack/host_throttle.hpp"

#include "ofquack/circuit_breaker.hpp"

#include <cstdint>
#include <unordered_map>

namespace ofquack {

HostThrottle::HostThrottle(uint32_t max_concurrent) : available(max_concurrent == 0 ? 1 : max_concurrent) {
}

HostThrottle::Slot::Slot(HostThrottle &owner_p) : owner(owner_p) {
	std::unique_lock<std::mutex> guard(owner.lock);
	owner.slot_freed.wait(guard, [this]() { return owner.available > 0; });
	owner.available--;
}

HostThrottle::Slot::~Slot() {
	{
		std::lock_guard<std::mutex> guard(owner.lock);
		owner.available++;
	}
	owner.slot_freed.notify_one();
}

namespace {

struct HostRegistry {
	std::mutex lock;
	std::unordered_map<std::string, std::shared_ptr<HostThrottle>> throttles;
	std::unordered_map<std::string, std::shared_ptr<CircuitBreaker>> breakers;
};

HostRegistry &Registry() {
	static HostRegistry registry;
	return registry;
}

} // namespace

std::string HostOf(const std::string &url) {
	auto rest = url;
	const auto scheme = rest.find("://");
	if (scheme != std::string::npos) {
		rest = rest.substr(scheme + 3);
	}
	const auto path = rest.find_first_of("/?#");
	if (path != std::string::npos) {
		rest = rest.substr(0, path);
	}
	// Credentials in the authority would make two spellings of one host look
	// like two hosts, and would put a password into an error message.
	const auto at = rest.rfind('@');
	if (at != std::string::npos) {
		rest = rest.substr(at + 1);
	}
	return rest;
}

std::string NormalizeFusionEndpoint(const std::string &endpoint) {
	auto trimmed = endpoint;
	const auto first = trimmed.find_first_not_of(" \t\r\n");
	if (first == std::string::npos) {
		return {};
	}
	const auto last = trimmed.find_last_not_of(" \t\r\n");
	trimmed = trimmed.substr(first, last - first + 1);

	const auto scheme_end = trimmed.find("://");
	const auto scheme = scheme_end == std::string::npos ? std::string("https://") : trimmed.substr(0, scheme_end + 3);
	auto rest = scheme_end == std::string::npos ? trimmed : trimmed.substr(scheme_end + 3);

	// Anything past the authority is the user's own choice of path, including a
	// query string, and is kept.
	const auto path_start = rest.find_first_of("/?#");
	if (path_start != std::string::npos) {
		const auto path = rest.substr(path_start);
		if (path != "/") {
			return scheme + rest;
		}
		rest = rest.substr(0, path_start);
	}
	if (rest.empty()) {
		return {};
	}
	return scheme + rest + "/xmlpserver/services/ExternalReportWSSService?WSDL";
}

std::shared_ptr<HostThrottle> ThrottleForHost(const std::string &host, uint32_t max_concurrent) {
	auto &registry = Registry();
	std::lock_guard<std::mutex> guard(registry.lock);
	auto entry = registry.throttles.find(host);
	if (entry != registry.throttles.end()) {
		// The first caller's limit wins; a later one asking for more would
		// otherwise quietly widen a limit the server is relying on.
		return entry->second;
	}
	auto throttle = std::make_shared<HostThrottle>(max_concurrent);
	registry.throttles.emplace(host, throttle);
	return throttle;
}

std::shared_ptr<CircuitBreaker> BreakerForHost(const std::string &host, const CircuitBreakerSettings &settings) {
	auto &registry = Registry();
	std::lock_guard<std::mutex> guard(registry.lock);
	auto entry = registry.breakers.find(host);
	if (entry != registry.breakers.end()) {
		return entry->second;
	}
	auto breaker = std::make_shared<CircuitBreaker>(settings);
	registry.breakers.emplace(host, breaker);
	return breaker;
}

void ResetHostStateForTesting() {
	auto &registry = Registry();
	std::lock_guard<std::mutex> guard(registry.lock);
	registry.throttles.clear();
	registry.breakers.clear();
}

} // namespace ofquack
