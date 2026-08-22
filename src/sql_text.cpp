#include "ofquack/sql_text.hpp"

#include <cctype>

namespace ofquack {

namespace {

enum class State { CODE, STRING, QUOTED_IDENT, LINE_COMMENT, BLOCK_COMMENT, HINT };

bool IsIdentifierChar(char c) {
	const auto uc = static_cast<unsigned char>(c);
	return std::isalnum(uc) || c == '_' || c == '$' || c == '#';
}

bool EqualsIgnoringCase(char a, char b) {
	return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
}

//! Walks the statement, calling `visit(state, index)` for every character with
//! the state it belongs to. Both NormalizeSql and FindKeyword need the same
//! lexing; writing it twice is how the two drift apart.
template <typename Visitor>
void Lex(const std::string &sql, Visitor &&visit) {
	State state = State::CODE;
	size_t i = 0;
	while (i < sql.size()) {
		const char c = sql[i];
		const char next = i + 1 < sql.size() ? sql[i + 1] : '\0';
		switch (state) {
		case State::CODE:
			if (c == '\'') {
				state = State::STRING;
			} else if (c == '"') {
				state = State::QUOTED_IDENT;
			} else if (c == '-' && next == '-') {
				state = State::LINE_COMMENT;
				visit(state, i);
				visit(state, i + 1);
				i += 2;
				continue;
			} else if (c == '/' && next == '*') {
				// A hint is a comment to the lexer but part of the statement to
				// Oracle, so it is tracked separately and survives normalisation.
				state = (i + 2 < sql.size() && sql[i + 2] == '+') ? State::HINT : State::BLOCK_COMMENT;
				visit(state, i);
				visit(state, i + 1);
				i += 2;
				continue;
			}
			visit(state, i);
			i++;
			continue;

		case State::STRING:
			visit(state, i);
			if (c == '\'') {
				if (next == '\'') {
					// Doubled quote is an escaped quote, still inside the literal.
					visit(state, i + 1);
					i += 2;
					continue;
				}
				state = State::CODE;
			}
			i++;
			continue;

		case State::QUOTED_IDENT:
			visit(state, i);
			if (c == '"') {
				state = State::CODE;
			}
			i++;
			continue;

		case State::LINE_COMMENT:
			visit(state, i);
			if (c == '\n') {
				state = State::CODE;
			}
			i++;
			continue;

		case State::BLOCK_COMMENT:
		case State::HINT:
			visit(state, i);
			if (c == '*' && next == '/') {
				visit(state, i + 1);
				state = State::CODE;
				i += 2;
				continue;
			}
			i++;
			continue;
		}
	}
}

} // namespace

std::string NormalizeSql(const std::string &sql) {
	std::string out;
	out.reserve(sql.size());
	bool pending_space = false;

	Lex(sql, [&](State state, size_t index) {
		if (index >= sql.size()) {
			return;
		}
		const char c = sql[index];
		switch (state) {
		case State::LINE_COMMENT:
		case State::BLOCK_COMMENT:
			// Dropped, but a comment separates tokens, so it leaves a space.
			pending_space = true;
			return;
		case State::CODE:
			if (std::isspace(static_cast<unsigned char>(c))) {
				pending_space = true;
				return;
			}
			break;
		default:
			break;
		}
		if (pending_space && !out.empty()) {
			out.push_back(' ');
		}
		pending_space = false;
		out.push_back(c);
	});

	// Trim: leading space is suppressed above, trailing may remain.
	const auto last = out.find_last_not_of(" \t\r\n");
	if (last == std::string::npos) {
		return {};
	}
	out.resize(last + 1);
	return out;
}

size_t FindKeyword(const std::string &sql, const std::string &keyword) {
	if (keyword.empty()) {
		return std::string::npos;
	}
	size_t found = std::string::npos;

	Lex(sql, [&](State state, size_t index) {
		if (found != std::string::npos || state != State::CODE || index >= sql.size()) {
			return;
		}
		if (index + keyword.size() > sql.size()) {
			return;
		}
		for (size_t k = 0; k < keyword.size(); k++) {
			if (!EqualsIgnoringCase(sql[index + k], keyword[k])) {
				return;
			}
		}
		// Word boundaries, so OFFSETS does not match OFFSET.
		if (index > 0 && IsIdentifierChar(sql[index - 1])) {
			return;
		}
		const auto after = index + keyword.size();
		if (after < sql.size() && IsIdentifierChar(sql[after])) {
			return;
		}
		found = index;
	});
	return found;
}

bool IsSelectStatement(const std::string &sql) {
	const auto normalized = NormalizeSql(sql);
	size_t at = 0;
	while (at < normalized.size() && std::isspace(static_cast<unsigned char>(normalized[at]))) {
		at++;
	}
	// A parenthesised SELECT is still a SELECT.
	while (at < normalized.size() && normalized[at] == '(') {
		at++;
		while (at < normalized.size() && std::isspace(static_cast<unsigned char>(normalized[at]))) {
			at++;
		}
	}
	for (const auto *prefix : {"SELECT", "WITH"}) {
		const std::string keyword = prefix;
		if (at + keyword.size() > normalized.size()) {
			continue;
		}
		bool matches = true;
		for (size_t k = 0; k < keyword.size(); k++) {
			if (!EqualsIgnoringCase(normalized[at + k], keyword[k])) {
				matches = false;
				break;
			}
		}
		const auto after = at + keyword.size();
		if (matches && (after >= normalized.size() || !IsIdentifierChar(normalized[after]))) {
			return true;
		}
	}
	return false;
}

} // namespace ofquack
