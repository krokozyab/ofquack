#pragma once

#include "duckdb.hpp"
#include "duckdb/planner/table_filter.hpp"

namespace duckdb {

//! One column as the catalog knows it.
struct FusionColumn {
	string name;
	LogicalType type;
	//! False when the type was guessed from data rather than read from Fusion's
	//! dictionary. Filters are never pushed on such a column: the comparison
	//! Oracle would perform and the one DuckDB would perform need not agree.
	bool type_from_dictionary = false;
};

//! Translates the filters DuckDB handed to a scan into an Oracle WHERE clause.
//!
//! Once DuckDB gives a filter to a scan it removes it from the plan, so
//! whatever is returned here must be applied *exactly*. Anything that cannot be
//! translated with certainty throws NotImplementedException rather than being
//! approximated -- an approximate filter is a silently wrong answer.
//!
//! `scanned_columns` maps a filter's key to a column: the keys of
//! TableFilterSet are indexes into the projection, not column ids.
string BuildOracleWhereClause(const TableFilterSet &filters, const vector<FusionColumn> &columns,
                              const vector<column_t> &scanned_columns);

} // namespace duckdb
