#include "ofquack/sql_rewrite.hpp"

#include "ofquack/sql_text.hpp"

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

std::string ApplyPagination(const std::string &normalized_sql, uint64_t offset, uint64_t fetch_size) {
	auto statement = normalized_sql;
	// A trailing semicolon is legal in a client but not inside the report's
	// bind variable, and it would land in the middle of the rewritten text.
	while (!statement.empty() && (statement.back() == ';' || statement.back() == ' ')) {
		statement.pop_back();
	}
	return statement + " OFFSET " + std::to_string(offset) + " ROWS FETCH NEXT " + std::to_string(fetch_size) +
	       " ROWS ONLY";
}

} // namespace ofquack
