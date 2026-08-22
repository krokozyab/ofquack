#include "ofquack/jwt.hpp"

#include "base64.h"

#include <cctype>
#include <cstdlib>

namespace ofquack {

namespace {

//! Value of a top-level JSON field, without a JSON parser.
//!
//! A JWT payload is a flat object of a handful of fields, and this runs on a
//! string the browser just handed us. Pulling in a parser for `exp` would be
//! more machinery than the problem needs.
bool FindField(const std::string &json, const std::string &name, std::string &value, bool &is_string) {
	const auto key = "\"" + name + "\"";
	auto at = json.find(key);
	while (at != std::string::npos) {
		auto cursor = at + key.size();
		while (cursor < json.size() && std::isspace(static_cast<unsigned char>(json[cursor]))) {
			cursor++;
		}
		if (cursor >= json.size() || json[cursor] != ':') {
			at = json.find(key, at + 1);
			continue;
		}
		cursor++;
		while (cursor < json.size() && std::isspace(static_cast<unsigned char>(json[cursor]))) {
			cursor++;
		}
		if (cursor >= json.size()) {
			return false;
		}
		if (json[cursor] == '"') {
			const auto start = ++cursor;
			std::string text;
			while (cursor < json.size() && json[cursor] != '"') {
				if (json[cursor] == '\\' && cursor + 1 < json.size()) {
					cursor++;
				}
				text.push_back(json[cursor]);
				cursor++;
			}
			(void)start;
			value = text;
			is_string = true;
			return true;
		}
		const auto start = cursor;
		while (cursor < json.size() && json[cursor] != ',' && json[cursor] != '}') {
			cursor++;
		}
		value = json.substr(start, cursor - start);
		while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) {
			value.pop_back();
		}
		is_string = false;
		return true;
	}
	return false;
}

} // namespace

std::string DecodeBase64Url(const std::string &encoded) {
	std::string standard;
	standard.reserve(encoded.size() + 3);
	for (const char c : encoded) {
		if (c == '-') {
			standard.push_back('+');
		} else if (c == '_') {
			standard.push_back('/');
		} else {
			standard.push_back(c);
		}
	}
	// base64url omits padding; the decoder wants it.
	while (standard.size() % 4 != 0) {
		standard.push_back('=');
	}
	try {
		return base64_decode(standard);
	} catch (const std::exception &) {
		return {};
	}
}

JwtClaims ParseJwtClaims(const std::string &token) {
	JwtClaims claims;

	const auto first_dot = token.find('.');
	if (first_dot == std::string::npos) {
		return claims;
	}
	const auto second_dot = token.find('.', first_dot + 1);
	if (second_dot == std::string::npos) {
		return claims;
	}

	const auto payload = DecodeBase64Url(token.substr(first_dot + 1, second_dot - first_dot - 1));
	if (payload.empty() || payload.front() != '{') {
		return claims;
	}
	claims.parsed = true;

	std::string value;
	bool is_string = false;
	if (FindField(payload, "exp", value, is_string) && !value.empty()) {
		claims.expires_at_epoch = std::strtoll(value.c_str(), nullptr, 10);
	}
	if (FindField(payload, "sub", value, is_string)) {
		claims.subject = value;
	}
	return claims;
}

} // namespace ofquack
