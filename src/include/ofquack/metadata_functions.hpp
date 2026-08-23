#pragma once

#include "duckdb.hpp"

namespace duckdb {

//! Registers the metadata and cache table functions:
//! oracle_fusion_tables, oracle_fusion_columns, fusion_scanner_cache_status,
//! fusion_scanner_cache_invalidate.
void RegisterFusionMetadataFunctions(ExtensionLoader &loader);

} // namespace duckdb
