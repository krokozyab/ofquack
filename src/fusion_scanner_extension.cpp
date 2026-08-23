#define DUCKDB_EXTENSION_MAIN

#include "fusion_scanner_extension.hpp"

#include "duckdb.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "ofquack/fusion_query_function.hpp"
#include "ofquack/fusion_secret.hpp"
#include "ofquack/fusion_catalog.hpp"
#include "ofquack/metadata_functions.hpp"
#include "ofquack/sso_functions.hpp"

#include <curl/curl.h>
#include <mutex>

namespace duckdb {

namespace {

//! libcurl requires one global initialisation before any easy handle exists.
//! There is deliberately no paired curl_global_cleanup: the extension ABI has
//! no shutdown hook to call it from, and calling it from a static destructor
//! would race libcurl's background threads.
void EnsureCurlInitialized() {
	static std::once_flag curl_init_flag;
	std::call_once(curl_init_flag, []() { curl_global_init(CURL_GLOBAL_DEFAULT); });
}

} // namespace

//! Reports the version *and* when this binary was compiled.
//!
//! DuckDB keeps a loaded extension for the life of the process, so a client
//! that holds a connection open -- a JDBC pool, DBeaver -- goes on using the
//! copy it loaded first, and a rebuilt file changes nothing until the client
//! restarts. Without a way to see which binary is in memory, that looks like a
//! fix that did not work.
void OfquackVersion(DataChunk &args, ExpressionState &, Vector &result) {
	const std::string version =
#ifdef EXT_VERSION_FUSION_SCANNER
	    EXT_VERSION_FUSION_SCANNER
#else
	    "dev"
#endif
	    " (built " __DATE__ " " __TIME__ ")";
	result.SetVectorType(VectorType::CONSTANT_VECTOR);
	ConstantVector::GetData<string_t>(result)[0] = StringVector::AddString(result, version);
}

static void LoadInternal(ExtensionLoader &loader) {
	EnsureCurlInitialized();
	loader.SetDescription("Query Oracle Fusion via BI Publisher SOAP calls");

	loader.RegisterFunction(ScalarFunction("fusion_scanner_version", {}, LogicalType::VARCHAR, OfquackVersion));

	RegisterFusionSecrets(loader);
	RegisterFusionQueryFunction(loader);
	RegisterFusionMetadataFunctions(loader);
	RegisterFusionCatalog(loader);
	RegisterFusionSsoFunctions(loader);
}

void FusionScannerExtension::Load(ExtensionLoader &loader) {
	LoadInternal(loader);
}

std::string FusionScannerExtension::Name() {
	return "fusion_scanner";
}

std::string FusionScannerExtension::Version() const {
#ifdef EXT_VERSION_FUSION_SCANNER
	return EXT_VERSION_FUSION_SCANNER;
#else
	return "";
#endif
}

} // namespace duckdb

extern "C" {

DUCKDB_CPP_EXTENSION_ENTRY(fusion_scanner, loader) {
	duckdb::LoadInternal(loader);
}

} // extern "C"
