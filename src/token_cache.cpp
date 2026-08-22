#include "ofquack/token_cache.hpp"

#include "ofquack/jwt.hpp"

#include <algorithm>
#include <chrono>
#include <mutex>
#include <unordered_map>

namespace ofquack {

namespace {

struct CacheState {
	std::mutex lock;
	std::unordered_map<std::string, CachedToken> tokens;
	std::function<int64_t()> now = []() {
		return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
		    .count();
	};
};

CacheState &State() {
	static CacheState state;
	return state;
}

} // namespace

TokenCache &TokenCache::Get() {
	static TokenCache cache;
	return cache;
}

void TokenCache::SetClockForTesting(std::function<int64_t()> clock) {
	auto &state = State();
	std::lock_guard<std::mutex> guard(state.lock);
	state.now = std::move(clock);
}

CachedToken TokenCache::Lookup(const std::string &host) {
	auto &state = State();
	std::lock_guard<std::mutex> guard(state.lock);
	const auto entry = state.tokens.find(host);
	if (entry == state.tokens.end()) {
		return {};
	}
	// The buffer is applied here rather than at store time, so a token that has
	// aged past usefulness reports itself as absent.
	if (state.now() >= entry->second.expires_at_epoch) {
		return {};
	}
	return entry->second;
}

void TokenCache::Store(const std::string &host, const std::string &access_token, const std::string &refresh_token,
                       int64_t expires_in_seconds) {
	auto &state = State();
	std::lock_guard<std::mutex> guard(state.lock);

	CachedToken token;
	token.access_token = access_token;
	token.refresh_token = refresh_token;
	token.obtained_at_epoch = state.now();

	// The JWT's own exp is the most trustworthy source; expires_in from the
	// relay is next; a fixed lifetime is the fallback for a token that says
	// nothing about itself.
	const auto claims = ParseJwtClaims(access_token);
	token.subject = claims.subject;
	int64_t expires_at = 0;
	if (claims.parsed && claims.expires_at_epoch > 0) {
		expires_at = claims.expires_at_epoch;
	} else if (expires_in_seconds > 0) {
		expires_at = token.obtained_at_epoch + expires_in_seconds;
	} else {
		expires_at = token.obtained_at_epoch + FALLBACK_TOKEN_LIFETIME_SECONDS;
	}
	// The safety margin is capped at half the token's life. A token valid for
	// two minutes would otherwise be discarded the moment it arrived, since the
	// margin alone exceeds it -- and a short token is still better than none.
	const auto lifetime = expires_at - token.obtained_at_epoch;
	const auto margin = std::min<int64_t>(TOKEN_EXPIRY_BUFFER_SECONDS, lifetime > 0 ? lifetime / 2 : 0);
	token.expires_at_epoch = expires_at - margin;

	state.tokens[host] = std::move(token);
}

void TokenCache::Forget(const std::string &host) {
	auto &state = State();
	std::lock_guard<std::mutex> guard(state.lock);
	state.tokens.erase(host);
}

void TokenCache::Clear() {
	auto &state = State();
	std::lock_guard<std::mutex> guard(state.lock);
	state.tokens.clear();
}

bool TokenCache::ShouldRefresh(const std::string &host) {
	auto &state = State();
	std::lock_guard<std::mutex> guard(state.lock);
	const auto entry = state.tokens.find(host);
	if (entry == state.tokens.end()) {
		return true;
	}
	const auto &token = entry->second;
	const auto lifetime = token.expires_at_epoch - token.obtained_at_epoch;
	if (lifetime <= 0) {
		return true;
	}
	const auto refresh_at =
	    token.obtained_at_epoch + static_cast<int64_t>(static_cast<double>(lifetime) * TOKEN_REFRESH_AT_FRACTION);
	return state.now() >= refresh_at;
}

} // namespace ofquack
