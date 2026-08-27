#pragma once

#include "duckdb.hpp"

#include <cstdint>

namespace duckdb {

//! Rows per dictionary page. A table-function parameter takes precedence over
//! the connection setting; callers without named parameters pass an empty map.
uint64_t MetadataPageSize(ClientContext &context, const named_parameter_map_t &named_parameters);

//! Registers the metadata and cache table functions:
//! oracle_fusion_tables, oracle_fusion_columns, fusion_scanner_cache_warm,
//! fusion_scanner_cache_status, fusion_scanner_cache_invalidate.
void RegisterFusionMetadataFunctions(ExtensionLoader &loader);

} // namespace duckdb
