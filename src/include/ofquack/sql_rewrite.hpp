#pragma once

#include <cstdint>
#include <string>
#include <vector>

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

//! True when the statement carries an ORDER BY of its own.
//!
//! OFFSET/FETCH partitions a result the server has ordered. Without an ORDER BY
//! Oracle is free to return the rows of one execution in a different order from
//! the next, and every page is a separate execution -- so pages can repeat rows
//! and skip others while each one looks perfectly well formed.
bool HasOrderBy(const std::string &normalized_sql);

//! Appends "ORDER BY 1, 2, ... n" over the given 1-based select-list positions.
//!
//! Ordering by every column of the output is a total order on the rows as the
//! caller sees them: two rows that tie on all of them are interchangeable, so
//! where a page boundary falls between them does not change the answer.
std::string AppendOrderByPositions(const std::string &sql, const std::vector<uint64_t> &positions);

//! Wraps a statement so a positional ORDER BY applies to its whole output.
//! Used when the caller wrote the statement and we may not edit its select list.
std::string WrapWithOrderBy(const std::string &normalized_sql, size_t column_count);

//! The same wrapper over a chosen subset of 1-based positions, for when some
//! columns must stay out of the order -- a CLOB cannot be sorted by.
std::string WrapWithOrderByPositions(const std::string &normalized_sql, const std::vector<uint64_t> &positions);

//! A statement that asks Oracle whether it will order `sql` by these 1-based
//! positions, without making it do any work: the inner ROWNUM keeps it to one
//! row, and the refusal -- ORA-00932 for a LOB, ORA-00997 for a LONG -- is
//! raised at compile time regardless of data. There is no function in Oracle
//! SQL that reports the type of a CLOB column (DUMP and VSIZE both reject
//! it), so the refusal itself is the only probe there is.
std::string OrderProbe(const std::string &normalized_sql, const std::vector<uint64_t> &positions);

//! How a key value read back from the report is written into the next page's
//! seek predicate. The report hands every value over as text; what the text
//! means depends on the column's type, and Oracle has to be told in a way
//! that no session setting (NLS_DATE_FORMAT above all) can reinterpret.
enum class KeyKind { NUMBER, TEXT, DATE, TIMESTAMP, ROWID };

//! The Oracle literal for a key value, or empty when the text cannot be one --
//! an empty string, which Oracle stores as NULL and cannot seek past, or a
//! number that is not a number.
std::string KeyLiteral(KeyKind kind, const std::string &text);

//! "Strictly after this row" in the order of the given expressions, expanded
//! the way Oracle needs it -- it has no row-value comparison outside IN:
//!   (a > :a OR (a = :a AND b > :b) OR (a = :a AND b = :b AND c > :c))
std::string SeekPredicate(const std::vector<std::string> &expressions, const std::vector<std::string> &literals);

} // namespace ofquack
