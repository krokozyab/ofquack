#pragma once

#include <cstdint>
#include <string>

namespace ofquack {

struct BrowserAuthSettings {
	//! Fusion host to sign in to, e.g. https://host.fa.em2.oraclecloud.com
	std::string login_url;
	//! Explicit browser binary. Empty means search the usual places.
	std::string chrome_path;
	//! Profile directory. Empty means ~/.ofquack/chrome-profile.
	std::string profile_dir;
	//! Use a throwaway profile, so nothing is remembered between runs.
	bool use_temp_profile = false;
	int64_t timeout_seconds = 300;
};

struct BrowserAuthResult {
	std::string access_token;
	std::string refresh_token;
	int64_t expires_in_seconds = 0;
	std::string subject;
};

//! Signs in through a real browser and comes back with a bearer token.
//!
//! The browser does the authentication -- Okta, Entra, a smartcard, whatever
//! the organisation uses -- and this only collects the result. Fusion hands a
//! signed-in session its own token through /fscmRestApi/tokenrelay, so no
//! client secret, no registered application, and no password ever reaches this
//! process.
//!
//! Blocking and interactive: it opens a window and waits for a person. Only
//! call it from somewhere a person is expecting that.
BrowserAuthResult AuthenticateThroughBrowser(const BrowserAuthSettings &settings);

//! Path of the browser to drive, or empty if none was found.
//! Order: OFQUACK_CHROME_PATH, then the usual install locations.
std::string FindBrowser(const std::string &configured_path);

//! Where to send the browser when the secret does not say.
//!
//! The report endpoint and the application live on the same host, and reaching
//! the application unauthenticated is what triggers the sign-on redirect -- so
//! the scheme and host of the endpoint are all that is needed. sso_login_url
//! exists for the instances where they are not: a separate vanity host, or a
//! sign-in that has to start at a particular page.
std::string DefaultLoginUrl(const std::string &endpoint);

//! The JavaScript run in the signed-in page to collect the token. Exposed so a
//! test can assert the endpoints it uses without launching anything.
const char *TokenCollectionScript();

} // namespace ofquack
