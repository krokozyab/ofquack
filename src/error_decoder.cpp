#include "ofquack/error_decoder.hpp"

#include <algorithm>
#include <cctype>
#include <vector>

namespace ofquack {

namespace {

std::string Trim(const std::string &text) {
	const auto first = text.find_first_not_of(" \t\r\n");
	if (first == std::string::npos) {
		return {};
	}
	const auto last = text.find_last_not_of(" \t\r\n");
	return text.substr(first, last - first + 1);
}

std::string CollapseWhitespace(const std::string &text) {
	std::string collapsed;
	collapsed.reserve(text.size());
	bool in_space = false;
	for (const char c : text) {
		if (std::isspace(static_cast<unsigned char>(c))) {
			in_space = true;
			continue;
		}
		if (in_space && !collapsed.empty()) {
			collapsed.push_back(' ');
		}
		in_space = false;
		collapsed.push_back(c);
	}
	return collapsed;
}

std::string Truncate(std::string text) {
	if (text.size() > MAX_REPORTED_ERROR_LENGTH) {
		text.resize(MAX_REPORTED_ERROR_LENGTH);
		text += "… (truncated)";
	}
	return text;
}

bool MatchesIgnoringCase(const std::string &text, size_t at, const std::string &needle) {
	if (at + needle.size() > text.size()) {
		return false;
	}
	for (size_t i = 0; i < needle.size(); i++) {
		if (std::tolower(static_cast<unsigned char>(text[at + i])) !=
		    std::tolower(static_cast<unsigned char>(needle[i]))) {
			return false;
		}
	}
	return true;
}

size_t FindIgnoringCase(const std::string &text, const std::string &needle, size_t from = 0) {
	for (size_t i = from; i + needle.size() <= text.size(); i++) {
		if (MatchesIgnoringCase(text, i, needle)) {
			return i;
		}
	}
	return std::string::npos;
}

//! Text of the first element with this local name, ignoring any namespace
//! prefix. Deliberately not a parser: these responses are frequently malformed,
//! and a strict parse would fail exactly when an explanation is most wanted.
std::string TextOfElement(const std::string &xml, const std::string &local_name) {
	size_t search_from = 0;
	while (search_from < xml.size()) {
		const auto open = xml.find('<', search_from);
		if (open == std::string::npos) {
			return {};
		}
		auto name_start = open + 1;
		// Skip a namespace prefix if one is present.
		const auto tag_end = xml.find_first_of(" \t\r\n>/", name_start);
		if (tag_end == std::string::npos) {
			return {};
		}
		const auto colon = xml.rfind(':', tag_end);
		if (colon != std::string::npos && colon > open) {
			name_start = colon + 1;
		}
		const auto name = xml.substr(name_start, tag_end - name_start);
		if (MatchesIgnoringCase(name, 0, local_name) && name.size() == local_name.size()) {
			const auto content_start = xml.find('>', tag_end);
			if (content_start == std::string::npos) {
				return {};
			}
			const auto close = xml.find('<', content_start + 1);
			if (close == std::string::npos) {
				return {};
			}
			return Trim(xml.substr(content_start + 1, close - content_start - 1));
		}
		search_from = open + 1;
	}
	return {};
}

} // namespace

std::string ExtractOracleErrors(const std::string &text) {
	std::vector<std::string> messages;
	size_t search_from = 0;
	for (;;) {
		const auto found = text.find("ORA-", search_from);
		if (found == std::string::npos) {
			break;
		}
		// "ORA-" must be followed by five digits and a colon to count.
		const auto digits_start = found + 4;
		if (digits_start + 5 > text.size()) {
			break;
		}
		bool five_digits = true;
		for (size_t i = 0; i < 5; i++) {
			if (!std::isdigit(static_cast<unsigned char>(text[digits_start + i]))) {
				five_digits = false;
				break;
			}
		}
		if (!five_digits) {
			search_from = found + 4;
			continue;
		}
		// Runs to the next ORA- code, or to the end of the enclosing element,
		// or to the end of the text -- whichever comes first. Without the '<'
		// bound a code inside <faultstring> would drag the closing tags and
		// everything after them into the message.
		const auto next = text.find("ORA-", digits_start + 5);
		const auto markup = text.find('<', digits_start + 5);
		auto message_end = std::min(next, markup);
		const auto message = Trim(CollapseWhitespace(
		    text.substr(found, message_end == std::string::npos ? std::string::npos : message_end - found)));
		if (!message.empty()) {
			messages.push_back(message);
		}
		if (next == std::string::npos) {
			break;
		}
		search_from = next;
	}

	std::string joined;
	for (const auto &message : messages) {
		if (!joined.empty()) {
			joined += "; ";
		}
		joined += message;
	}
	return joined;
}

std::string DescribeFailure(const std::string &response) {
	// Oracle's own codes say what actually failed, so they win over whatever
	// wrapper the fault arrived in.
	const auto oracle_errors = ExtractOracleErrors(response);
	if (!oracle_errors.empty()) {
		return Truncate(oracle_errors);
	}

	// SOAP 1.2 nests the message in Fault/Reason/Text; SOAP 1.1 uses faultstring.
	if (FindIgnoringCase(response, "<") != std::string::npos) {
		for (const auto *element : {"faultstring", "Text", "faultcode", "exceptionName"}) {
			const auto text = TextOfElement(response, element);
			if (!text.empty()) {
				return Truncate(CollapseWhitespace(text));
			}
		}
	}

	// A login redirect or a gateway error arrives as an HTML page.
	if (FindIgnoringCase(response, "<html") != std::string::npos) {
		for (const auto *element : {"title", "h1"}) {
			const auto text = TextOfElement(response, element);
			if (!text.empty()) {
				return Truncate(CollapseWhitespace(text));
			}
		}
		return "the server returned an HTML page instead of a SOAP response "
		       "(often a login redirect: check the credentials and the endpoint)";
	}
	return {};
}

} // namespace ofquack
