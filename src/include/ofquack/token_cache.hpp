#pragma once

#include <cstdint>
#include <functional>
#include <string>

namespace ofquack {

struct CachedToken {
	std::string access_token;
	std::string refresh_token;
	std::string subject;
	int64_t obtained_at_epoch = 0;
	int64_t expires_at_epoch = 0;

	bool Valid() const {
		return !access_token.empty();
	}
};

//! When a token has no usable `exp`, assume it lasts this long. Fusion issues
//! one-hour tokens; 55 minutes leaves room to notice.
constexpr int64_t FALLBACK_TOKEN_LIFETIME_SECONDS = 55 * 60;

//! Treat a token as expired this long before it really is, so a request never
//! goes out with a token that dies in flight.
constexpr int64_t TOKEN_EXPIRY_BUFFER_SECONDS = 5 * 60;

//! Refresh once this much of the token's life has passed, rather than waiting
//! for it to expire: an interactive login in the middle of a query is far worse
//! than one that happens between queries.
constexpr double TOKEN_REFRESH_AT_FRACTION = 0.8;

//! Live bearer tokens, keyed by Fusion host.
//!
//! Process-wide, and deliberately not per connection: obtaining one is
//! interactive and expensive, so tying it to a DuckDB connection would mean a
//! new browser window per connection. It is also never written to disk -- the
//! browser profile holds the long-lived cookie, and that is enough to get a new
//! token without a new login.
class TokenCache {
public:
	static TokenCache &Get();

	//! The token for `host`, if one is held and still usable.
	CachedToken Lookup(const std::string &host);

	//! Stores a token, deriving its expiry from the JWT when it has one.
	void Store(const std::string &host, const std::string &access_token, const std::string &refresh_token,
	           int64_t expires_in_seconds);

	void Forget(const std::string &host);
	void Clear();

	//! True when the token is old enough to be worth replacing.
	bool ShouldRefresh(const std::string &host);

	//! Test seam.
	static void SetClockForTesting(std::function<int64_t()> clock);
};

} // namespace ofquack
