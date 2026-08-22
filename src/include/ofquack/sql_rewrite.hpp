#pragma once

#include <cstdint>
#include <string>

namespace ofquack {

//! Why a statement cannot be paged, or Yes if it can.
enum class PaginationVerdict {
	YES,
	//! Not a SELECT: paging a call or a PL/SQL block is meaningless.
	NOT_A_SELECT,
	//! Already limited by the author. Wrapping ours around theirs would change
	//! which rows come back, so their intent wins and paging is skipped.
	ALREADY_LIMITED,
	//! Uses ROWNUM, which is assigned before ORDER BY and does not compose with
	//! OFFSET: pairing them silently returns the wrong rows.
	USES_ROWNUM,
	//! Paging was turned off.
	DISABLED,
};

//! Decides whether `sql` can be paged. Expects normalised SQL.
PaginationVerdict ClassifyForPagination(const std::string &normalized_sql, uint64_t fetch_size);

//! Appends the Oracle 12c row-limiting clause. Only valid when
//! ClassifyForPagination returned YES.
//!
//! BI Publisher's own chunking (sizeOfDataChunkDownload) is not used; rewriting
//! the statement is the only paging mechanism the report exposes.
std::string ApplyPagination(const std::string &normalized_sql, uint64_t offset, uint64_t fetch_size);

} // namespace ofquack
