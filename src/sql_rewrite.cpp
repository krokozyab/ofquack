#include "ofquack/sql_rewrite.hpp"

#include "ofquack/sql_text.hpp"

#include <vector>

namespace ofquack {

PaginationVerdict ClassifyForPagination(const std::string &normalized_sql, uint64_t fetch_size) {
	if (fetch_size == 0) {
		return PaginationVerdict::DISABLED;
	}
	if (!IsSelectStatement(normalized_sql)) {
		return PaginationVerdict::NOT_A_SELECT;
	}
	// Keyword search, not substring search: SELECT 'OFFSET' FROM t is pageable.
	if (FindKeyword(normalized_sql, "OFFSET") != std::string::npos ||
	    FindKeyword(normalized_sql, "FETCH") != std::string::npos) {
		return PaginationVerdict::ALREADY_LIMITED;
	}
	if (FindKeyword(normalized_sql, "ROWNUM") != std::string::npos) {
		return PaginationVerdict::USES_ROWNUM;
	}
	return PaginationVerdict::YES;
}

namespace {

//! Drops a trailing semicolon, which is legal in a client but not inside the
//! report's bind variable, where it would land in the middle of the rewrite.
std::string Trimmed(const std::string &sql) {
	auto statement = sql;
	while (!statement.empty() && (statement.back() == ';' || statement.back() == ' ')) {
		statement.pop_back();
	}
	return statement;
}

} // namespace

std::string ApplyPagination(const std::string &normalized_sql, uint64_t offset, uint64_t fetch_size) {
	return Trimmed(normalized_sql) + " OFFSET " + std::to_string(offset) + " ROWS FETCH NEXT " +
	       std::to_string(fetch_size) + " ROWS ONLY";
}

bool HasOrderBy(const std::string &normalized_sql) {
	// ORDER only introduces the clause when BY comes straight after it. On its
	// own it is a column name in plenty of places, and BY on its own belongs to
	// GROUP BY and PARTITION BY at least as often.
	for (size_t at = 0;;) {
		const auto order = FindKeyword(normalized_sql, "ORDER", at);
		if (order == std::string::npos) {
			return false;
		}
		const auto after = order + 5;
		const auto by = FindKeyword(normalized_sql, "BY", after);
		if (by != std::string::npos && normalized_sql.find_first_not_of(" \t\r\n", after) == by) {
			return true;
		}
		at = after;
	}
}

std::string AppendOrderByPositions(const std::string &sql, const std::vector<uint64_t> &positions) {
	if (positions.empty()) {
		return Trimmed(sql);
	}
	std::string clause = " ORDER BY ";
	for (size_t i = 0; i < positions.size(); i++) {
		if (i > 0) {
			clause += ", ";
		}
		clause += std::to_string(positions[i]);
	}
	return Trimmed(sql) + clause;
}

std::string WrapWithOrderBy(const std::string &normalized_sql, size_t column_count) {
	std::vector<uint64_t> positions;
	positions.reserve(column_count);
	for (size_t i = 1; i <= column_count; i++) {
		positions.push_back(static_cast<uint64_t>(i));
	}
	// Wrapped rather than edited: the caller wrote this statement, and appending
	// to it would attach the ORDER BY to whichever query happens to come last in
	// a UNION rather than to the result as a whole.
	return AppendOrderByPositions("SELECT * FROM (" + Trimmed(normalized_sql) + ")", positions);
}

std::string WrapWithOrderByPositions(const std::string &normalized_sql, const std::vector<uint64_t> &positions) {
	return AppendOrderByPositions("SELECT * FROM (" + Trimmed(normalized_sql) + ")", positions);
}

std::string OrderProbe(const std::string &normalized_sql, const std::vector<uint64_t> &positions) {
	return AppendOrderByPositions("SELECT * FROM (SELECT * FROM (" + Trimmed(normalized_sql) + ") WHERE ROWNUM <= 1)",
	                              positions);
}

} // namespace ofquack
