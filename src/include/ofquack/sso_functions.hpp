#pragma once

#include "duckdb.hpp"

namespace duckdb {

//! Registers fusion_scanner_sso_login, fusion_scanner_sso_status and fusion_scanner_sso_logout.
void RegisterFusionSsoFunctions(ExtensionLoader &loader);

} // namespace duckdb
