#pragma once

#include <string>
#include <vector>

namespace ofquack {

//! Fusion exposes its dictionary through the same report as everything else,
//! so each of these is an ordinary statement sent through BI Publisher. They
//! are ported from the JDBC driver unchanged, because they are what has been
//! shown to work against real instances -- not because every choice in them is
//! one this code would make.
//!
//! Two of those choices are load-bearing and must not be "tidied":
//!
//!  * Tables and views come from FND_VIEWS and FND_TABLES rather than from
//!    ALL_TABLES, since Fusion's own dictionary is what carries TABLE_ID, and
//!    TABLE_ID is how columns are looked up.
//!  * The column queries alias data_precision as DECIMAL_DIGITS and data_scale
//!    as NUM_PREC_RADIX -- shifted by one from what the names suggest. The type
//!    mapper reads them in that shifted sense, so correcting one without the
//!    other turns NUMBER(10,0) into DECIMAL(0,10).
namespace metadata {

//! Rows are limited by an outer ROWNUM wrapper rather than OFFSET/FETCH: these
//! statements are built by concatenation and may already end in ORDER BY.
//!
//! Kept below the point where BI Publisher truncates a response. It silently
//! returns fewer rows than asked for rather than reporting anything, so a page
//! size above that limit does not fail -- it quietly loses the rest of the
//! dictionary. The same limit is why columns are fetched ten tables at a time.
constexpr uint64_t PAGE_SIZE = 400;

//! Columns are fetched for several tables at once, but not too many: the report
//! truncates a response beyond roughly 500 rows, and ten tables of thirty
//! columns stays under that.
constexpr size_t COLUMN_BATCH_SIZE = 10;

//! Fusion's dictionary presents everything under one schema.
constexpr const char *SCHEMA = "FUSION";

//! Wraps a statement so it returns rows (offset, offset + PAGE_SIZE].
std::string PaginateByRownum(const std::string &base_sql, uint64_t offset, uint64_t page_size = PAGE_SIZE);

//! Tables and views. `types` is a list such as {"TABLE", "VIEW"}.
std::string TablesByTypes(const std::vector<std::string> &types);

//! How many tables and views the dictionary holds.
//!
//! One row, so it cannot be truncated, and it is what makes a partial listing
//! detectable: without it, a listing that stopped early is indistinguishable
//! from an instance that simply has fewer tables.
std::string TableCount(const std::vector<std::string> &types);

//! Columns of the given tables, looked up by the TABLE_ID that TablesByTypes
//! returned.
std::string ColumnsByTableIds(const std::vector<std::string> &table_ids);

//! Columns of a view. Views are not in FND_COLUMNS, so ALL_TAB_COLUMNS is the
//! only source; `table_name_pattern` is a LIKE pattern.
std::string ColumnsOfViews(const std::string &table_name_pattern);

std::string PrimaryKeys(const std::string &table_name);
std::string ForeignKeys(const std::string &table_name);
std::string Indexes(const std::string &table_name, bool unique_only);

//! Escapes a value for embedding in a single-quoted Oracle literal.
//!
//! The JDBC driver interpolates these patterns raw, so a name containing an
//! apostrophe breaks the statement -- and would let one through.
std::string QuoteLiteral(const std::string &value);

} // namespace metadata
} // namespace ofquack
