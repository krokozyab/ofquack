#include "ofquack/websocket.hpp"

#include "base64.h"
#include "ofquack/errors.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstring>
#include <openssl/sha.h>
#include <random>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
using socket_t = SOCKET;
static constexpr socket_t INVALID_SOCKET_HANDLE = INVALID_SOCKET;
#define CLOSE_SOCKET closesocket
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
using socket_t = int;
static constexpr socket_t INVALID_SOCKET_HANDLE = -1;
#define CLOSE_SOCKET ::close
#endif

namespace ofquack {

namespace {

//! From RFC 6455: appended to the client key before hashing.
constexpr const char *WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

constexpr uint8_t OPCODE_CONTINUATION = 0x0;
constexpr uint8_t OPCODE_TEXT = 0x1;
constexpr uint8_t OPCODE_CLOSE = 0x8;
constexpr uint8_t OPCODE_PING = 0x9;
constexpr uint8_t OPCODE_PONG = 0xA;

int64_t NowMs() {
	return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch())
	    .count();
}

std::string RandomKey() {
	std::random_device device;
	std::uniform_int_distribution<int> byte_distribution(0, 255);
	unsigned char nonce[16];
	for (auto &value : nonce) {
		value = static_cast<unsigned char>(byte_distribution(device));
	}
	return base64_encode(nonce, sizeof(nonce));
}

} // namespace

bool ParseWebSocketUrl(const std::string &url, std::string &host, uint16_t &port, std::string &path) {
	static const std::string SCHEME = "ws://";
	if (url.compare(0, SCHEME.size(), SCHEME) != 0) {
		return false;
	}
	auto rest = url.substr(SCHEME.size());
	const auto slash = rest.find('/');
	path = slash == std::string::npos ? "/" : rest.substr(slash);
	auto authority = slash == std::string::npos ? rest : rest.substr(0, slash);

	const auto colon = authority.rfind(':');
	if (colon == std::string::npos) {
		host = authority;
		port = 80;
		return !host.empty();
	}
	host = authority.substr(0, colon);
	const auto port_text = authority.substr(colon + 1);
	if (host.empty() || port_text.empty()) {
		return false;
	}
	for (const char c : port_text) {
		if (!std::isdigit(static_cast<unsigned char>(c))) {
			return false;
		}
	}
	port = static_cast<uint16_t>(std::stoi(port_text));
	return true;
}

std::string ComputeWebSocketAccept(const std::string &key) {
	const auto combined = key + WEBSOCKET_GUID;
	unsigned char digest[SHA_DIGEST_LENGTH];
	SHA1(reinterpret_cast<const unsigned char *>(combined.c_str()), combined.size(), digest);
	return base64_encode(digest, sizeof(digest));
}

struct WebSocket::Impl {
	socket_t handle = INVALID_SOCKET_HANDLE;
	//! Bytes read from the socket but not yet consumed as frames.
	std::vector<uint8_t> buffer;
	bool closed = false;

	~Impl() {
		if (handle != INVALID_SOCKET_HANDLE) {
			CLOSE_SOCKET(handle);
		}
	}

	void SendAll(const uint8_t *data, size_t length) {
		size_t sent = 0;
		while (sent < length) {
			const auto written =
			    send(handle, reinterpret_cast<const char *>(data + sent), static_cast<int>(length - sent), 0);
			if (written <= 0) {
				throw RetryableError("The browser debugging connection was closed while sending");
			}
			sent += static_cast<size_t>(written);
		}
	}

	//! Reads whatever is available, waiting at most `timeout_ms`. Returns false
	//! on timeout or a closed connection.
	bool ReadSome(int64_t timeout_ms) {
		timeval timeout {};
		timeout.tv_sec = static_cast<decltype(timeout.tv_sec)>(timeout_ms / 1000);
		timeout.tv_usec = static_cast<decltype(timeout.tv_usec)>((timeout_ms % 1000) * 1000);

		fd_set readable;
		FD_ZERO(&readable);
		FD_SET(handle, &readable);
		const int ready = select(static_cast<int>(handle) + 1, &readable, nullptr, nullptr, &timeout);
		if (ready <= 0) {
			return false;
		}

		char chunk[8192];
		const auto received = recv(handle, chunk, sizeof(chunk), 0);
		if (received <= 0) {
			closed = true;
			return false;
		}
		buffer.insert(buffer.end(), chunk, chunk + received);
		return true;
	}

	//! Frames a payload. Client frames must be masked, per RFC 6455.
	void SendFrame(uint8_t opcode, const std::string &payload) {
		std::vector<uint8_t> frame;
		frame.push_back(static_cast<uint8_t>(0x80 | opcode)); // FIN set: no fragmentation on send

		const auto length = payload.size();
		if (length < 126) {
			frame.push_back(static_cast<uint8_t>(0x80 | length));
		} else if (length <= 0xFFFF) {
			frame.push_back(static_cast<uint8_t>(0x80 | 126));
			frame.push_back(static_cast<uint8_t>((length >> 8) & 0xFF));
			frame.push_back(static_cast<uint8_t>(length & 0xFF));
		} else {
			// CDP payloads can exceed 64 KiB, so the 64-bit form is required.
			frame.push_back(static_cast<uint8_t>(0x80 | 127));
			for (int shift = 56; shift >= 0; shift -= 8) {
				frame.push_back(static_cast<uint8_t>((length >> shift) & 0xFF));
			}
		}

		std::random_device device;
		std::uniform_int_distribution<int> byte_distribution(0, 255);
		uint8_t mask[4];
		for (auto &value : mask) {
			value = static_cast<uint8_t>(byte_distribution(device));
			frame.push_back(value);
		}
		for (size_t i = 0; i < length; i++) {
			frame.push_back(static_cast<uint8_t>(payload[i]) ^ mask[i % 4]);
		}
		SendAll(frame.data(), frame.size());
	}

	//! Pulls one complete frame out of the buffer, if there is one.
	bool TryTakeFrame(uint8_t &opcode, bool &final_fragment, std::string &payload) {
		if (buffer.size() < 2) {
			return false;
		}
		final_fragment = (buffer[0] & 0x80) != 0;
		opcode = buffer[0] & 0x0F;
		const bool masked = (buffer[1] & 0x80) != 0;
		uint64_t length = buffer[1] & 0x7F;
		size_t cursor = 2;

		if (length == 126) {
			if (buffer.size() < cursor + 2) {
				return false;
			}
			length = (static_cast<uint64_t>(buffer[2]) << 8) | buffer[3];
			cursor += 2;
		} else if (length == 127) {
			if (buffer.size() < cursor + 8) {
				return false;
			}
			length = 0;
			for (size_t i = 0; i < 8; i++) {
				length = (length << 8) | buffer[cursor + i];
			}
			cursor += 8;
		}

		// A server must not mask, but handling it costs four lines.
		uint8_t mask[4] = {0, 0, 0, 0};
		if (masked) {
			if (buffer.size() < cursor + 4) {
				return false;
			}
			std::memcpy(mask, buffer.data() + cursor, 4);
			cursor += 4;
		}
		if (buffer.size() < cursor + length) {
			return false;
		}

		payload.assign(length, '\0');
		for (uint64_t i = 0; i < length; i++) {
			const auto byte = buffer[cursor + i];
			payload[i] = static_cast<char>(masked ? (byte ^ mask[i % 4]) : byte);
		}
		buffer.erase(buffer.begin(), buffer.begin() + static_cast<long>(cursor + length));
		return true;
	}
};

WebSocket::WebSocket(const std::string &url) : impl(new Impl()) {
	std::string host;
	uint16_t port = 0;
	std::string path;
	if (!ParseWebSocketUrl(url, host, port, path)) {
		throw PermanentError("Not a usable WebSocket URL: " + url);
	}

#ifdef _WIN32
	WSADATA winsock_data;
	WSAStartup(MAKEWORD(2, 2), &winsock_data);
#endif

	impl->handle = socket(AF_INET, SOCK_STREAM, 0);
	if (impl->handle == INVALID_SOCKET_HANDLE) {
		throw PermanentError("Could not open a socket to the browser");
	}

	sockaddr_in address {};
	address.sin_family = AF_INET;
	address.sin_port = htons(port);
	if (inet_pton(AF_INET, host.c_str(), &address.sin_addr) != 1) {
		// The debugging port is always on loopback; anything else is a mistake
		// rather than something to resolve.
		throw PermanentError("The browser debugging address must be a loopback IP, not " + host);
	}
	if (connect(impl->handle, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0) {
		throw RetryableError("Could not connect to the browser debugging port");
	}

	const int one = 1;
	setsockopt(impl->handle, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char *>(&one), sizeof(one));

	const auto key = RandomKey();
	const std::string request = "GET " + path +
	                            " HTTP/1.1\r\n"
	                            "Host: " +
	                            host + ":" + std::to_string(port) +
	                            "\r\n"
	                            "Upgrade: websocket\r\n"
	                            "Connection: Upgrade\r\n"
	                            "Sec-WebSocket-Key: " +
	                            key +
	                            "\r\n"
	                            "Sec-WebSocket-Version: 13\r\n\r\n";
	impl->SendAll(reinterpret_cast<const uint8_t *>(request.c_str()), request.size());

	// Read until the end of the response headers; anything after them is the
	// first frame and must stay in the buffer.
	const auto deadline = NowMs() + 10000;
	size_t header_end = std::string::npos;
	for (;;) {
		const std::string seen(impl->buffer.begin(), impl->buffer.end());
		header_end = seen.find("\r\n\r\n");
		if (header_end != std::string::npos) {
			const auto status_line_end = seen.find("\r\n");
			const auto status_line = seen.substr(0, status_line_end);
			if (status_line.find(" 101") == std::string::npos) {
				throw PermanentError("The browser refused the debugging connection: " + status_line);
			}
			// Header names are case insensitive, so the search is done on a
			// lowered copy of the header block while the value is taken from
			// the original.
			const auto headers = seen.substr(0, header_end);
			auto lowered = headers;
			std::transform(lowered.begin(), lowered.end(), lowered.begin(),
			               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

			static const std::string ACCEPT_HEADER = "sec-websocket-accept:";
			const auto accept_at = lowered.find(ACCEPT_HEADER);
			if (accept_at == std::string::npos) {
				throw PermanentError("The browser did not complete the WebSocket handshake");
			}
			const auto value_start = accept_at + ACCEPT_HEADER.size();
			// The last header of the block has no trailing CRLF inside it,
			// because the block was cut at the blank line -- so a missing CRLF
			// means "to the end", not an error.
			auto line_end = lowered.find("\r\n", value_start);
			if (line_end == std::string::npos) {
				line_end = headers.size();
			}
			auto value = headers.substr(value_start, line_end - value_start);
			const auto first = value.find_first_not_of(" \t");
			const auto last = value.find_last_not_of(" \t");
			value = first == std::string::npos ? std::string() : value.substr(first, last - first + 1);

			const auto expected = ComputeWebSocketAccept(key);
			if (value != expected) {
				throw PermanentError("The browser returned a bad WebSocket handshake (expected " + expected +
				                     ", got '" + value + "')");
			}
			break;
		}
		if (NowMs() > deadline || !impl->ReadSome(500)) {
			if (NowMs() > deadline) {
				throw RetryableError("The browser did not answer the WebSocket handshake in time");
			}
			if (impl->closed) {
				throw RetryableError("The browser closed the debugging connection during the handshake");
			}
		}
	}
	impl->buffer.erase(impl->buffer.begin(), impl->buffer.begin() + static_cast<long>(header_end + 4));
}

WebSocket::~WebSocket() = default;

void WebSocket::SendText(const std::string &payload) {
	impl->SendFrame(OPCODE_TEXT, payload);
}

bool WebSocket::ReceiveText(std::string &payload, int64_t timeout_ms) {
	const auto deadline = NowMs() + timeout_ms;
	std::string assembled;
	bool assembling = false;

	for (;;) {
		uint8_t opcode = 0;
		bool final_fragment = false;
		std::string frame_payload;
		if (impl->TryTakeFrame(opcode, final_fragment, frame_payload)) {
			switch (opcode) {
			case OPCODE_PING:
				// Answering keeps Chrome from dropping the connection.
				impl->SendFrame(OPCODE_PONG, frame_payload);
				continue;
			case OPCODE_PONG:
				continue;
			case OPCODE_CLOSE:
				impl->closed = true;
				return false;
			case OPCODE_TEXT:
				assembled = frame_payload;
				assembling = true;
				break;
			case OPCODE_CONTINUATION:
				if (!assembling) {
					continue;
				}
				assembled += frame_payload;
				break;
			default:
				continue;
			}
			if (assembling && final_fragment) {
				payload = std::move(assembled);
				return true;
			}
			continue;
		}

		const auto remaining = deadline - NowMs();
		if (remaining <= 0 || impl->closed) {
			return false;
		}
		impl->ReadSome(remaining);
	}
}

void WebSocket::Close() {
	if (impl->closed || impl->handle == INVALID_SOCKET_HANDLE) {
		return;
	}
	try {
		impl->SendFrame(OPCODE_CLOSE, std::string("\x03\xe8", 2)); // 1000, normal closure
	} catch (const std::exception &) {
		// Already gone; nothing useful to do about it.
	}
	impl->closed = true;
}

} // namespace ofquack
