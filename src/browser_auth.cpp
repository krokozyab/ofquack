#include "ofquack/browser_auth.hpp"

#include "ofquack/errors.hpp"
#include "ofquack/http_curl.hpp"
#include "ofquack/json_util.hpp"
#include "ofquack/proc.hpp"
#include "ofquack/websocket.hpp"

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace ofquack {

namespace {

//! How often to ask the page whether a token is available yet. The person is
//! typing a password and possibly answering a second factor, so this is a slow
//! poll on purpose.
constexpr int64_t POLL_INTERVAL_MS = 2000;
//! Chrome writes its debugging port and starts listening within a second or so.
constexpr int64_t PORT_WAIT_MS = 10000;

std::string HomeDirectory() {
#ifdef _WIN32
	const char *profile = std::getenv("USERPROFILE");
	return profile ? profile : "";
#else
	const char *home = std::getenv("HOME");
	return home ? home : "";
#endif
}

bool PathExists(const std::string &path) {
	if (path.empty()) {
		return false;
	}
#ifdef _WIN32
	return GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES;
#else
	struct stat info {};
	return stat(path.c_str(), &info) == 0;
#endif
}

void EnsureDirectory(const std::string &path) {
	if (path.empty() || PathExists(path)) {
		return;
	}
#ifdef _WIN32
	CreateDirectoryA(path.c_str(), nullptr);
#else
	mkdir(path.c_str(), 0700);
#endif
}

std::string EnvironmentValue(const char *name) {
	const char *value = std::getenv(name);
	return value ? value : "";
}

} // namespace

const char *TokenCollectionScript() {
	// Runs inside the signed-in Fusion page, so it inherits the session cookie.
	// The anti-CSRF token has to be fetched first: tokenrelay rejects a request
	// without it, which is what stops another site from doing this.
	return R"JS((async () => {
  try {
    const csrfResponse = await fetch('/fscmRestApi/anticsrf', {method: 'GET', credentials: 'same-origin'});
    if (!csrfResponse.ok) { return {status: 'waiting'}; }
    const csrf = await csrfResponse.json();
    const relayResponse = await fetch('/fscmRestApi/tokenrelay', {
      method: 'GET',
      credentials: 'same-origin',
      headers: {'X-XSRF-TOKEN': csrf.xsrftoken}
    });
    if (!relayResponse.ok) { return {status: 'waiting'}; }
    const data = await relayResponse.json();
    if (!data.access_token || data.access_token.length < 50) { return {status: 'waiting'}; }
    return {
      status: 'success',
      token: data.access_token,
      refreshToken: data.refresh_token || '',
      expiresIn: data.expires_in || 0
    };
  } catch (error) {
    return {status: 'waiting', detail: String(error)};
  }
})())JS";
}

std::string DefaultLoginUrl(const std::string &endpoint) {
	if (endpoint.empty()) {
		return {};
	}
	const auto scheme_end = endpoint.find("://");
	const auto scheme = scheme_end == std::string::npos ? std::string("https://") : endpoint.substr(0, scheme_end + 3);
	auto rest = scheme_end == std::string::npos ? endpoint : endpoint.substr(scheme_end + 3);

	const auto path = rest.find_first_of("/?#");
	if (path != std::string::npos) {
		rest = rest.substr(0, path);
	}
	// Credentials in the authority would otherwise be handed to the browser.
	const auto at = rest.rfind('@');
	if (at != std::string::npos) {
		rest = rest.substr(at + 1);
	}
	return rest.empty() ? std::string() : scheme + rest;
}

std::string FindBrowser(const std::string &configured_path) {
	// Not const: a const local cannot be moved out of on return.
	auto from_environment = EnvironmentValue("OFQUACK_CHROME_PATH");
	if (!from_environment.empty()) {
		return from_environment;
	}
	if (!configured_path.empty()) {
		return configured_path;
	}

	// Edge is included because a managed Windows desktop often has it and not
	// Chrome, and it speaks the same debugging protocol.
	static const char *const CANDIDATES[] = {
#ifdef _WIN32
	    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
	    "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
	    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
	    "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
#elif defined(__APPLE__)
	    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
	    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
	    "/Applications/Chromium.app/Contents/MacOS/Chromium",
	    "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
#else
	    "/usr/bin/google-chrome",
	    "/usr/bin/google-chrome-stable",
	    "/usr/bin/chromium",
	    "/usr/bin/chromium-browser",
	    "/snap/bin/chromium",
	    "/usr/bin/microsoft-edge",
#endif
	};

#ifdef _WIN32
	const auto local_app_data = EnvironmentValue("LOCALAPPDATA");
	if (!local_app_data.empty()) {
		const auto user_install = local_app_data + "\\Google\\Chrome\\Application\\chrome.exe";
		if (PathExists(user_install)) {
			return user_install;
		}
	}
#endif

	for (const auto *candidate : CANDIDATES) {
		if (PathExists(candidate)) {
			return candidate;
		}
	}
	return {};
}

namespace {

//! The page target Chrome opened, found through its HTTP debugging endpoint.
std::string FindPageWebSocketUrl(uint16_t port) {
	HttpClient client;
	HttpRequest request;
	request.url = "http://127.0.0.1:" + std::to_string(port) + "/json/list";
	request.connect_timeout_seconds = 5;
	request.read_timeout_seconds = 5;
	// The debugging endpoint answers a GET; an empty POST body is not accepted,
	// so this is issued as a GET by libcurl's default for an empty body.
	auto response = client.Get(request);
	if (response.status_code != 200) {
		throw RetryableError("The browser debugging endpoint returned HTTP " +
		                     std::to_string(response.status_code));
	}

	const auto targets = json::ParseArray(response.body);
	for (const auto &target : targets) {
		if (json::StringField(target, "type") == "page") {
			const auto url = json::StringField(target, "webSocketDebuggerUrl");
			if (!url.empty()) {
				return url;
			}
		}
	}
	throw RetryableError("The browser has no page open to sign in with");
}

//! One Chrome, one debugging connection, one login.
class BrowserSession {
public:
	BrowserSession(const std::string &executable, const BrowserAuthSettings &settings, const std::string &profile_dir,
	               uint16_t port)
	    : process(executable, {
	                              "--remote-debugging-port=" + std::to_string(port),
	                              "--user-data-dir=" + profile_dir,
	                              "--no-first-run",
	                              "--no-default-browser-check",
	                              "--disable-background-networking",
	                              "--disable-sync",
	                              settings.login_url,
	                          }) {
	}

	//! True once the debugging port answers. False when the process died first,
	//! which is what happens when Chrome hands the URL to an instance that is
	//! already running and exits -- the caller retries with a fresh profile.
	bool WaitForPort(uint16_t port) {
		const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(PORT_WAIT_MS);
		while (std::chrono::steady_clock::now() < deadline) {
			if (IsLoopbackPortOpen(port)) {
				return true;
			}
			if (!process.IsRunning()) {
				return false;
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(250));
		}
		return false;
	}

private:
	ChildProcess process;
};

BrowserAuthResult PollForToken(WebSocket &socket, const BrowserAuthSettings &settings) {
	int next_message_id = 1;
	const auto send = [&](const std::string &method, const std::string &params) {
		const auto message = "{\"id\":" + std::to_string(next_message_id++) + ",\"method\":\"" + method +
		                     "\",\"params\":" + params + "}";
		socket.SendText(message);
	};

	send("Runtime.enable", "{}");
	send("Page.enable", "{}");

	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(settings.timeout_seconds);
	while (std::chrono::steady_clock::now() < deadline) {
		const auto expression = json::QuoteString(TokenCollectionScript());
		send("Runtime.evaluate",
		     "{\"expression\":" + expression + ",\"awaitPromise\":true,\"returnByValue\":true}");

		// Chrome interleaves events with replies, so keep reading until the
		// evaluation result turns up or the poll interval runs out.
		const auto poll_until = std::chrono::steady_clock::now() + std::chrono::milliseconds(POLL_INTERVAL_MS);
		while (std::chrono::steady_clock::now() < poll_until) {
			std::string message;
			if (!socket.ReceiveText(message, 500)) {
				continue;
			}
			if (json::StringField(message, "status") != "success") {
				continue;
			}
			BrowserAuthResult result;
			result.access_token = json::StringField(message, "token");
			if (result.access_token.empty()) {
				continue;
			}
			result.refresh_token = json::StringField(message, "refreshToken");
			result.expires_in_seconds = json::IntegerField(message, "expiresIn");
			return result;
		}
	}
	throw PermanentError("Timed out waiting for the Oracle Fusion sign-in to complete after " +
	                     std::to_string(settings.timeout_seconds) +
	                     "s. Sign in in the browser window, or raise sso_timeout_seconds");
}

BrowserAuthResult RunOnce(const std::string &executable, const BrowserAuthSettings &settings,
                          const std::string &profile_dir, bool &port_failed) {
	const auto port = FindFreeLoopbackPort();
	BrowserSession session(executable, settings, profile_dir, port);
	if (!session.WaitForPort(port)) {
		port_failed = true;
		throw RetryableError("The browser did not open a debugging port");
	}
	port_failed = false;

	WebSocket socket(FindPageWebSocketUrl(port));
	auto result = PollForToken(socket, settings);
	socket.Close();
	return result;
}

} // namespace

BrowserAuthResult AuthenticateThroughBrowser(const BrowserAuthSettings &settings) {
	const auto executable = FindBrowser(settings.chrome_path);
	if (executable.empty()) {
		throw PermanentError(
		    "No Chrome, Chromium or Edge was found to sign in with. Set OFQUACK_CHROME_PATH, or pass "
		    "chrome_path on the secret, or obtain a token another way and use AUTH 'bearer'");
	}
	if (settings.login_url.empty()) {
		throw PermanentError("Browser sign-in needs the Fusion URL to open: set sso_login_url on the secret");
	}

	auto profile_dir = settings.profile_dir;
	if (profile_dir.empty()) {
		const auto home = HomeDirectory();
		if (home.empty()) {
			throw PermanentError("Could not locate a home directory for the browser profile");
		}
		profile_dir = home + "/.ofquack";
		EnsureDirectory(profile_dir);
		profile_dir += "/chrome-profile";
	}
	EnsureDirectory(profile_dir);

	bool port_failed = false;
	try {
		return RunOnce(executable, settings, profile_dir, port_failed);
	} catch (const FusionError &) {
		if (!port_failed) {
			throw;
		}
	}

	// The browser exited without opening a port, which is what Chrome does when
	// it hands the URL to an instance that is already running under this
	// profile. A throwaway profile gets an independent process -- at the cost
	// of signing in again, since it carries no cookies.
	const auto temporary_profile = profile_dir + "-temp-" + std::to_string(FindFreeLoopbackPort());
	EnsureDirectory(temporary_profile);
	bool ignored = false;
	return RunOnce(executable, settings, temporary_profile, ignored);
}

} // namespace ofquack
