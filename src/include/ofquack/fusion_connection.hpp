#pragma once

#include "duckdb.hpp"
#include "ofquack/transport.hpp"

namespace duckdb {

//! Settings a scan needs beyond the connection itself.
struct FusionScanOptions {
	idx_t fetch_size = 500;
	bool secured_views = false;
};

//! Resolves the connection from a secret plus any overriding named parameters.
//!
//! Secret lookup, in order:
//!   1. `secret := 'name'`        -- looked up by name;
//!   2. `endpoint := 'https://…'` -- looked up by scope, longest prefix wins;
//!   3. neither                   -- the only oracle_fusion secret, if there is
//!                                   exactly one.
//! Named parameters override whatever the secret carries.
ofquack::FusionConfig ResolveFusionConfig(ClientContext &context, const named_parameter_map_t &named_parameters,
                                          FusionScanOptions &options);

//! Registers `secret`, `endpoint`, `report_path`, `fetch_size` and friends on a
//! table function, so every entry point accepts the same spelling.
void AddFusionNamedParameters(TableFunction &function);

} // namespace duckdb
