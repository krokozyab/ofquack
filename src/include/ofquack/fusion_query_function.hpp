#pragma once

#include "duckdb.hpp"

namespace duckdb {

//! Registers oracle_fusion_query(), plus a stub for the removed positional
//! function that explains how to migrate.
void RegisterFusionQueryFunction(ExtensionLoader &loader);

} // namespace duckdb
