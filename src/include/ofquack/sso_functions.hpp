#pragma once

#include "duckdb.hpp"

namespace duckdb {

//! Registers ofquack_sso_login, ofquack_sso_status and ofquack_sso_logout.
void RegisterFusionSsoFunctions(ExtensionLoader &loader);

} // namespace duckdb
