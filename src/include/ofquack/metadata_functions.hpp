#pragma once

#include "duckdb.hpp"

namespace duckdb {

//! Registers the metadata and cache table functions:
//! oracle_fusion_tables, oracle_fusion_columns, ofquack_cache_status,
//! ofquack_cache_invalidate.
void RegisterFusionMetadataFunctions(ExtensionLoader &loader);

} // namespace duckdb
