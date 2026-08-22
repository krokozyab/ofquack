#define DUCKDB_EXTENSION_MAIN

#include "ofquack_extension.hpp"

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

static void LoadInternal(ExtensionLoader &loader) {
	EnsureCurlInitialized();
	loader.SetDescription("Query Oracle Fusion via BI Publisher SOAP calls");

	RegisterFusionSecrets(loader);
	RegisterFusionQueryFunction(loader);
	RegisterFusionMetadataFunctions(loader);
	RegisterFusionCatalog(loader);
	RegisterFusionSsoFunctions(loader);
}

void OfquackExtension::Load(ExtensionLoader &loader) {
	LoadInternal(loader);
}

std::string OfquackExtension::Name() {
	return "ofquack";
}

std::string OfquackExtension::Version() const {
#ifdef EXT_VERSION_OFQUACK
	return EXT_VERSION_OFQUACK;
#else
	return "";
#endif
}

} // namespace duckdb

extern "C" {

DUCKDB_CPP_EXTENSION_ENTRY(ofquack, loader) {
	duckdb::LoadInternal(loader);
}

} // extern "C"
