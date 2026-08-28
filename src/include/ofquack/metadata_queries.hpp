#pragma once

#include <cstdint>
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

//! Table rows are narrow enough that the JDBC driver's proven page size is a
//! better default than the conservative value used for column metadata. The
//! setting fusion_scanner_metadata_page_size can still lower it for a Fusion
//! instance whose report or proxy accepts smaller responses.
constexpr uint64_t TABLE_LIST_PAGE_SIZE = 2000;

//! Column rows carry types and descriptions and have been observed to hit the
//! report's response limit around five hundred rows. Keep their paging limit
//! independent from the table-list setting so making name discovery faster
//! cannot silently make the wider query less reliable.
constexpr uint64_t COLUMN_PAGE_SIZE = 400;

//! Columns are fetched for several tables at once, but not too many: the report
//! truncates a response beyond roughly 500 rows, and ten tables of thirty
//! columns stays under that.
constexpr size_t COLUMN_BATCH_SIZE = 10;

//! The owner Fusion's dictionary objects live under. Every instance seen so far
//! uses this one, which is why it is a default rather than a required setting --
//! but the view and constraint queries filter on it, so a deployment that
//! differs has to be able to say so. `SCHEMA` on the secret overrides it.
//!
//! Not DEFAULT_SCHEMA: DuckDB defines that as a macro for "main"
//! (duckdb/common/constants.hpp), and this header is reached through duckdb.hpp.
constexpr const char *DICTIONARY_SCHEMA = "FUSION";

//! Limits a statement to rows (offset, offset + page_size].
//!
//! Uses Oracle's row-limiting clause rather than adding another SELECT/ROWNUM
//! wrapper around statements that already end in ORDER BY. This remains offset
//! paging because column batches are deliberately small and never run deep.
std::string PaginateByOffset(const std::string &base_sql, uint64_t offset, uint64_t page_size);

//! One page of tables and views, ordered by name, starting after the given
//! one. Pass empty strings for the first page.
//!
//! This is keyset paging, not OFFSET paging, and the difference is not an
//! optimisation. `OFFSET 5600` makes the server sort the whole union of
//! FND_VIEWS and FND_TABLES and then discard the first 5,600 rows, so each
//! page costs more than the last and is correspondingly more exposed to report
//! timeouts and resource limits. Seeking keeps that cost independent of depth.
//!
//! Seeking from the last name seen costs the same at any depth.
std::string TablesAfter(const std::string &schema, const std::vector<std::string> &types,
                        const std::string &after_name, const std::string &after_type, uint64_t page_size);

//! How many tables and views the dictionary holds.
//!
//! One row, so it cannot be truncated, and it is what makes a partial listing
//! detectable: without it, a listing that stopped early is indistinguishable
//! from an instance that simply has fewer tables.
std::string TableCount(const std::vector<std::string> &types);

//! Columns of the given tables, looked up by the TABLE_ID that TablesByTypes
//! returned.
std::string ColumnsByTableIds(const std::string &schema, const std::vector<std::string> &table_ids);

//! Columns of one view. Views are not in FND_COLUMNS, so ALL_TAB_COLUMNS is the
//! only source. The name is compared exactly: underscores in Oracle object
//! names must not become LIKE wildcards and merge several schemas together.
std::string ColumnsOfViews(const std::string &schema, const std::string &table_name);

std::string PrimaryKeys(const std::string &schema, const std::string &table_name);
std::string ForeignKeys(const std::string &schema, const std::string &table_name);
std::string Indexes(const std::string &schema, const std::string &table_name, bool unique_only);

//! Escapes a value for embedding in a single-quoted Oracle literal.
//!
//! The JDBC driver interpolates these patterns raw, so a name containing an
//! apostrophe breaks the statement -- and would let one through.
std::string QuoteLiteral(const std::string &value);

} // namespace metadata
} // namespace ofquack
