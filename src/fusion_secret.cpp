#include "ofquack/fusion_secret.hpp"

#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/secret/secret.hpp"

namespace duckdb {

namespace {

//! Every field a secret of this type may carry. Values absent from CREATE
//! SECRET stay unset, and the query function applies its own defaults.
const char *const SECRET_KEYS[] = {
    "endpoint",    "report_path", "auth",         "username",     "password",
    "token",       "schema",      "fetch_size",   "secured_views", "connect_timeout",
    "read_timeout", "on_cast_error", "number_mode",
};

unique_ptr<BaseSecret> CreateFusionSecretFromConfig(ClientContext &, CreateSecretInput &input) {
	auto secret = make_uniq<KeyValueSecret>(input.scope, input.type, input.provider, input.name);
	for (const auto &key : SECRET_KEYS) {
		secret->TrySetValue(key, input);
	}
	// Hides the values from duckdb_secrets(). Note this does NOT encrypt them:
	// CREATE PERSISTENT SECRET writes ~/.duckdb/stored_secrets in the clear.
	secret->redact_keys = {"password", "token"};
	return std::move(secret);
}

//! A browser secret holds only where to sign in, never a credential.
//!
//! Creating it does not open a browser: that would make CREATE SECRET
//! interactive, and it is often run from a script. The sign-in happens when
//! fusion_scanner_sso_login() is called, and the token lives in memory only.
unique_ptr<BaseSecret> CreateFusionSecretFromBrowser(ClientContext &, CreateSecretInput &input) {
	auto secret = make_uniq<KeyValueSecret>(input.scope, input.type, input.provider, input.name);
	for (const auto &key : SECRET_KEYS) {
		secret->TrySetValue(key, input);
	}
	for (const auto &key : {"sso_login_url", "chrome_path", "chrome_profile_dir", "use_temp_profile",
	                        "sso_timeout_seconds"}) {
		secret->TrySetValue(key, input);
	}
	secret->redact_keys = {"password", "token"};
	return std::move(secret);
}

void AddCommonParameters(CreateSecretFunction &function) {
	function.named_parameters["endpoint"] = LogicalType::VARCHAR;
	function.named_parameters["report_path"] = LogicalType::VARCHAR;
	function.named_parameters["schema"] = LogicalType::VARCHAR;
	function.named_parameters["fetch_size"] = LogicalType::UBIGINT;
	function.named_parameters["secured_views"] = LogicalType::BOOLEAN;
	function.named_parameters["on_cast_error"] = LogicalType::VARCHAR;
	function.named_parameters["number_mode"] = LogicalType::VARCHAR;
	function.named_parameters["connect_timeout"] = LogicalType::UBIGINT;
	function.named_parameters["read_timeout"] = LogicalType::UBIGINT;
}

} // namespace

void RegisterFusionSecrets(ExtensionLoader &loader) {
	SecretType type;
	type.name = "oracle_fusion";
	// Without a deserializer a persistent secret cannot be read back at startup.
	type.deserializer = KeyValueSecret::Deserialize<KeyValueSecret>;
	type.default_provider = "config";
	type.extension = "ofquack";
	loader.RegisterSecretType(std::move(type));

	CreateSecretFunction config_provider;
	config_provider.secret_type = "oracle_fusion";
	config_provider.provider = "config";
	config_provider.function = CreateFusionSecretFromConfig;
	AddCommonParameters(config_provider);
	config_provider.named_parameters["auth"] = LogicalType::VARCHAR;
	config_provider.named_parameters["username"] = LogicalType::VARCHAR;
	config_provider.named_parameters["password"] = LogicalType::VARCHAR;
	config_provider.named_parameters["token"] = LogicalType::VARCHAR;
	loader.RegisterFunction(std::move(config_provider));

	// Registered so the error says "not implemented yet" rather than "unknown
	// provider", which would read as a typo.
	CreateSecretFunction browser_provider;
	browser_provider.secret_type = "oracle_fusion";
	browser_provider.provider = "browser";
	browser_provider.function = CreateFusionSecretFromBrowser;
	AddCommonParameters(browser_provider);
	browser_provider.named_parameters["sso_login_url"] = LogicalType::VARCHAR;
	browser_provider.named_parameters["chrome_path"] = LogicalType::VARCHAR;
	browser_provider.named_parameters["chrome_profile_dir"] = LogicalType::VARCHAR;
	browser_provider.named_parameters["use_temp_profile"] = LogicalType::BOOLEAN;
	browser_provider.named_parameters["sso_timeout_seconds"] = LogicalType::UBIGINT;
	loader.RegisterFunction(std::move(browser_provider));
}

} // namespace duckdb
