#pragma once

#include "ofquack/transport.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace ofquack {

struct TableInfo {
	std::string name;
	std::string type; //!< TABLE or VIEW
	std::string remarks;
	std::string table_id; //!< FND id, used to look the columns up
};

struct ColumnInfo {
	std::string table_name;
	std::string name;
	std::string type_name;
	int64_t precision = 0;
	int64_t scale = 0;
	int64_t ordinal = 0;
	bool nullable = true;
	std::string remarks;
};

//! Lists tables and views. Cost: one request per TABLE_LIST_PAGE_SIZE rows, plus
//! the independent count and the confirmed terminal page.
//!
//! The extra request is the instance's own count, asked first and compared
//! against what the listing produced. A listing that comes back short throws
//! rather than returning: it would otherwise be cached and serve a partial
//! dictionary for a week, and a caller has no way of telling that from a
//! complete one. `expected_out` receives that count, or -1 if the instance
//! would not answer -- unknown is not the same as zero.
std::vector<TableInfo> FetchTables(FusionTransport &transport, const RequestContext &context, const std::string &schema,
                                   const std::vector<std::string> &types, uint64_t page_size = 0,
                                   int64_t *expected_out = nullptr);

//! How many distinct tables and views the dictionary holds, in one request.
//! Returns -1 when the instance will not answer.
int64_t FetchTableCount(FusionTransport &transport, const RequestContext &context, const std::string &schema,
                        const std::vector<std::string> &types);

//! Columns of several tables at once, in batches. Cost: one request per
//! COLUMN_BATCH_SIZE tables, which is why callers should ask for everything
//! they need in one call rather than looping.
std::vector<ColumnInfo> FetchColumnsOfTables(FusionTransport &transport, const RequestContext &context, const std::string &schema,
                                             const std::vector<TableInfo> &tables);

//! Columns of one view, which are not in FND_COLUMNS.
std::vector<ColumnInfo> FetchColumnsOfView(FusionTransport &transport, const RequestContext &context, const std::string &schema,
                                           const std::string &view_name);

//! One index: its name and its columns in position order.
struct IndexInfo {
	std::string name;
	std::vector<std::string> columns;
};

//! The unique indexes of a table, fewest columns first. A Fusion table often
//! has no declared primary key but does have a unique index (the _U1), which
//! serves the same purpose for ordering a paged read.
std::vector<IndexInfo> FetchUniqueIndexes(FusionTransport &transport, const RequestContext &context, const std::string &schema,
                                          const std::string &table_name);

//! Primary key column names, in key order. Empty when there is no primary key.
std::vector<std::string> FetchPrimaryKey(FusionTransport &transport, const RequestContext &context, const std::string &schema,
                                         const std::string &table_name);

} // namespace ofquack
