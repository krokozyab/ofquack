#pragma once

#include <cstdint>
#include <memory>
#include <string>

namespace ofquack {

//! A minimal RFC 6455 client, for talking to Chrome's debugging port.
//!
//! Written rather than taken from libcurl because libcurl's WebSocket API is
//! marked experimental in every released 8.x, needs curl built with
//! --enable-websockets, and could change under a vcpkg baseline bump.
//!
//! It is minimal because the one connection it ever makes is the simplest case
//! a WebSocket can be: ws://127.0.0.1:<port>, so no TLS, no proxy, no
//! redirects, and Chrome does not negotiate permessage-deflate. Do not reach
//! for this for anything else.
class WebSocket {
public:
	//! Connects and performs the HTTP upgrade. `url` must be ws://127.0.0.1:…
	explicit WebSocket(const std::string &url);
	~WebSocket();

	WebSocket(const WebSocket &) = delete;
	WebSocket &operator=(const WebSocket &) = delete;

	void SendText(const std::string &payload);

	//! Waits for one text message. Returns false on timeout or a closed
	//! connection. Control frames are handled internally.
	bool ReceiveText(std::string &payload, int64_t timeout_ms);

	void Close();

private:
	struct Impl;
	std::unique_ptr<Impl> impl;
};

//! Splits ws://host:port/path. Exposed for testing.
bool ParseWebSocketUrl(const std::string &url, std::string &host, uint16_t &port, std::string &path);

//! The Sec-WebSocket-Accept value a server must return for a given key.
std::string ComputeWebSocketAccept(const std::string &key);

} // namespace ofquack
