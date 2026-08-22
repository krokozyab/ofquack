#include "ofquack/json_util.hpp"

#include <cctype>
#include <cstdlib>

namespace ofquack {
namespace json {

namespace {

//! Position just past the colon of `"name":`, or npos.
size_t FindFieldValue(const std::string &document, const std::string &name) {
	const auto key = "\"" + name + "\"";
	auto at = document.find(key);
	while (at != std::string::npos) {
		auto cursor = at + key.size();
		while (cursor < document.size() && std::isspace(static_cast<unsigned char>(document[cursor]))) {
			cursor++;
		}
		if (cursor < document.size() && document[cursor] == ':') {
			cursor++;
			while (cursor < document.size() && std::isspace(static_cast<unsigned char>(document[cursor]))) {
				cursor++;
			}
			return cursor;
		}
		// The name appeared as a value rather than a key; keep looking.
		at = document.find(key, at + 1);
	}
	return std::string::npos;
}

std::string Unescape(const std::string &escaped) {
	std::string text;
	text.reserve(escaped.size());
	for (size_t i = 0; i < escaped.size(); i++) {
		if (escaped[i] != '\\' || i + 1 >= escaped.size()) {
			text.push_back(escaped[i]);
			continue;
		}
		switch (escaped[++i]) {
		case 'n':
			text.push_back('\n');
			break;
		case 't':
			text.push_back('\t');
			break;
		case 'r':
			text.push_back('\r');
			break;
		case 'b':
			text.push_back('\b');
			break;
		case 'f':
			text.push_back('\f');
			break;
		case 'u': {
			// Only the ASCII range is decoded; anything else is left alone,
			// since none of the fields read here carry non-ASCII text.
			if (i + 4 < escaped.size()) {
				const auto code = std::strtol(escaped.substr(i + 1, 4).c_str(), nullptr, 16);
				if (code > 0 && code < 128) {
					text.push_back(static_cast<char>(code));
					i += 4;
					break;
				}
			}
			text.push_back('u');
			break;
		}
		default:
			text.push_back(escaped[i]);
			break;
		}
	}
	return text;
}

} // namespace

std::string StringField(const std::string &document, const std::string &name) {
	auto cursor = FindFieldValue(document, name);
	if (cursor == std::string::npos || cursor >= document.size() || document[cursor] != '"') {
		return {};
	}
	cursor++;
	std::string escaped;
	while (cursor < document.size() && document[cursor] != '"') {
		if (document[cursor] == '\\' && cursor + 1 < document.size()) {
			escaped.push_back(document[cursor++]);
		}
		escaped.push_back(document[cursor++]);
	}
	return Unescape(escaped);
}

int64_t IntegerField(const std::string &document, const std::string &name) {
	const auto cursor = FindFieldValue(document, name);
	if (cursor == std::string::npos || cursor >= document.size()) {
		return 0;
	}
	if (document[cursor] != '-' && !std::isdigit(static_cast<unsigned char>(document[cursor]))) {
		return 0;
	}
	return std::strtoll(document.c_str() + cursor, nullptr, 10);
}

std::vector<std::string> ParseArray(const std::string &document) {
	std::vector<std::string> elements;
	const auto open = document.find('[');
	if (open == std::string::npos) {
		return elements;
	}

	int depth = 0;
	bool in_string = false;
	size_t element_start = std::string::npos;
	for (size_t i = open; i < document.size(); i++) {
		const char c = document[i];
		if (in_string) {
			if (c == '\\') {
				i++;
			} else if (c == '"') {
				in_string = false;
			}
			continue;
		}
		switch (c) {
		case '"':
			in_string = true;
			break;
		case '[':
		case '{':
			depth++;
			if (depth == 2 && element_start == std::string::npos) {
				element_start = i;
			}
			break;
		case ']':
		case '}':
			depth--;
			if (depth == 1 && element_start != std::string::npos) {
				elements.push_back(document.substr(element_start, i - element_start + 1));
				element_start = std::string::npos;
			}
			if (depth == 0) {
				return elements;
			}
			break;
		default:
			break;
		}
	}
	return elements;
}

std::string QuoteString(const std::string &text) {
	std::string quoted = "\"";
	for (const char c : text) {
		switch (c) {
		case '"':
			quoted += "\\\"";
			break;
		case '\\':
			quoted += "\\\\";
			break;
		case '\n':
			quoted += "\\n";
			break;
		case '\r':
			quoted += "\\r";
			break;
		case '\t':
			quoted += "\\t";
			break;
		default:
			if (static_cast<unsigned char>(c) < 0x20) {
				static const char *HEX = "0123456789abcdef";
				quoted += "\\u00";
				quoted.push_back(HEX[(c >> 4) & 0xF]);
				quoted.push_back(HEX[c & 0xF]);
			} else {
				quoted.push_back(c);
			}
			break;
		}
	}
	quoted.push_back('"');
	return quoted;
}

} // namespace json
} // namespace ofquack
