#pragma once

#include "duckdb.hpp"
#include "ofquack/browser_auth.hpp"
#include "ofquack/metadata_queries.hpp"
#include "ofquack/transport.hpp"

namespace duckdb {

//! Settings a scan needs beyond the connection itself.
struct FusionScanOptions {
	//! Filled in from the secret when browser sign-in is configured.
	ofquack::BrowserAuthSettings sso;
	//! Rows per request. 0 disables paging: one request, whatever comes back.
	idx_t fetch_size = 500;
	//! The owner the dictionary queries filter on. Part of the metadata cache
	//! key, so two secrets that differ only here do not share cached rows.
	std::string schema = ofquack::metadata::DICTIONARY_SCHEMA;
	bool secured_views = false;
	//! Skips type inference and returns every column as VARCHAR, for when a
	//! guess from the first page would be wrong for the rest of the data.
	bool all_varchar = false;
	//! Adds an ORDER BY over every column before paging, so that the pages of one
	//! result partition it rather than sampling it. Off only when Oracle refuses
	//! the ordering -- see fusion_scanner_stable_paging.
	bool stable_paging = true;
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

//! Fails when a bearer configuration has no token yet, naming the sign-in
//! function. Call from anything that is about to send a request; the SSO
//! functions deliberately do not.
void RequireUsableCredentials(const ofquack::FusionConfig &config);

//! Registers `secret`, `endpoint`, `report_path`, `fetch_size` and friends on a
//! table function, so every entry point accepts the same spelling.
void AddFusionNamedParameters(TableFunction &function);

} // namespace duckdb
