#pragma once

#include "ofquack/transport.hpp"

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

//! Lists tables and views. Cost: one request per PAGE_SIZE rows.
std::vector<TableInfo> FetchTables(FusionTransport &transport, const RequestContext &context,
                                   const std::vector<std::string> &types, uint64_t page_size = 0);

//! How many tables and views the dictionary holds, in one request.
//!
//! Compared against what a listing produced, this is what turns a silently
//! partial dictionary into a visible one. Returns -1 when the instance does
//! not answer -- unknown is not the same as zero, and must not be reported as
//! a shortfall.
int64_t FetchTableCount(FusionTransport &transport, const RequestContext &context,
                        const std::vector<std::string> &types);

//! Columns of several tables at once, in batches. Cost: one request per
//! COLUMN_BATCH_SIZE tables, which is why callers should ask for everything
//! they need in one call rather than looping.
std::vector<ColumnInfo> FetchColumnsOfTables(FusionTransport &transport, const RequestContext &context,
                                             const std::vector<TableInfo> &tables);

//! Columns of one view, which are not in FND_COLUMNS.
std::vector<ColumnInfo> FetchColumnsOfView(FusionTransport &transport, const RequestContext &context,
                                           const std::string &view_name);

//! Primary key column names, in key order. Empty when there is no primary key.
std::vector<std::string> FetchPrimaryKey(FusionTransport &transport, const RequestContext &context,
                                         const std::string &table_name);

} // namespace ofquack
