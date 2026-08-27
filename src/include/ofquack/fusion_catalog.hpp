#pragma once

#include "duckdb.hpp"

namespace duckdb {

//! Registers the `oracle_fusion` storage extension, so that
//!   ATTACH 'my_secret' AS f (TYPE oracle_fusion)
//! exposes Fusion's tables as an ordinary read-only catalog.
void RegisterFusionCatalog(ExtensionLoader &loader);

//! Regression seam for the lifetime of catalog metadata snapshots.
bool CatalogColumnsSurviveInvalidationForTesting(ClientContext &context);

} // namespace duckdb
