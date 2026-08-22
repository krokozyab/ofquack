#pragma once

#include "duckdb.hpp"

namespace duckdb {

//! Registers the `oracle_fusion` secret type and its providers.
void RegisterFusionSecrets(ExtensionLoader &loader);

} // namespace duckdb
