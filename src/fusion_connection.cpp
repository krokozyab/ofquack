#include "ofquack/fusion_connection.hpp"

#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "ofquack/host_throttle.hpp"
#include "ofquack/token_cache.hpp"

#include <algorithm>

namespace duckdb {

namespace {

constexpr const char *SECRET_TYPE = "oracle_fusion";
constexpr idx_t MIN_FETCH_SIZE = 1;
constexpr idx_t MAX_FETCH_SIZE = 10000;

std::string SecretString(const KeyValueSecret &secret, const char *key) {
	const auto value = secret.TryGetValue(key);
	return value.IsNull() ? std::string() : value.ToString();
}

const KeyValueSecret &AsFusionSecret(const SecretEntry &entry, const std::string &name) {
	const auto *secret = dynamic_cast<const KeyValueSecret *>(entry.secret.get());
	if (!secret || secret->GetType() != SECRET_TYPE) {
		throw BinderException("Secret '%s' is not an %s secret", name, SECRET_TYPE);
	}
	return *secret;
}

unique_ptr<SecretEntry> LookupByName(ClientContext &context, const std::string &name) {
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
	auto entry = SecretManager::Get(context).GetSecretByName(transaction, name);
	if (!entry || !entry->secret) {
		throw BinderException("%s secret '%s' was not found", SECRET_TYPE, name);
	}
	return entry;
}

unique_ptr<SecretEntry> LookupByEndpoint(ClientContext &context, const std::string &endpoint) {
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
	auto match = SecretManager::Get(context).LookupSecret(transaction, endpoint, SECRET_TYPE);
	if (!match.HasMatch()) {
		return nullptr;
	}
	return std::move(match.secret_entry);
}

//! The only secret of this type, if the database holds exactly one. Anything
//! else is reported rather than guessed: silently picking one of several would
//! send credentials to whichever instance happened to sort first.
unique_ptr<SecretEntry> LookupSoleSecret(ClientContext &context) {
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
	auto all = SecretManager::Get(context).AllSecrets(transaction);

	vector<string> candidates;
	for (auto &entry : all) {
		if (entry.secret && entry.secret->GetType() == SECRET_TYPE) {
			candidates.push_back(entry.secret->GetName());
		}
	}
	if (candidates.empty()) {
		throw BinderException("No %s secret is defined. Create one with:\n"
		                      "  CREATE SECRET fusion (TYPE %s, ENDPOINT '…', REPORT_PATH '…', "
		                      "USERNAME '…', PASSWORD '…')\n"
		                      "or pass secret := '<name>'",
		                      SECRET_TYPE, SECRET_TYPE);
	}
	if (candidates.size() > 1) {
		std::sort(candidates.begin(), candidates.end());
		throw BinderException("Several %s secrets are defined (%s); pass secret := '<name>' to choose one",
		                      SECRET_TYPE, StringUtil::Join(candidates, ", "));
	}
	return LookupByName(context, candidates[0]);
}

Value NamedParameter(const named_parameter_map_t &named_parameters, const char *key) {
	const auto entry = named_parameters.find(key);
	return entry == named_parameters.end() ? Value() : entry->second;
}

std::string NamedString(const named_parameter_map_t &named_parameters, const char *key) {
	const auto value = NamedParameter(named_parameters, key);
	return value.IsNull() ? std::string() : value.ToString();
}

} // namespace

void AddFusionNamedParameters(TableFunction &function) {
	function.named_parameters["secret"] = LogicalType::VARCHAR;
	function.named_parameters["endpoint"] = LogicalType::VARCHAR;
	function.named_parameters["report_path"] = LogicalType::VARCHAR;
	function.named_parameters["username"] = LogicalType::VARCHAR;
	function.named_parameters["password"] = LogicalType::VARCHAR;
	function.named_parameters["fetch_size"] = LogicalType::UBIGINT;
	function.named_parameters["secured_views"] = LogicalType::BOOLEAN;
	function.named_parameters["all_varchar"] = LogicalType::BOOLEAN;
}

void RequireUsableCredentials(const ofquack::FusionConfig &config) {
	// Checked before anything is sent, so a query that cannot possibly
	// authenticate fails immediately and says what to do about it.
	//
	// Not folded into ResolveFusionConfig, because the SSO functions resolve
	// the same configuration precisely in order to report on, or fix, the
	// missing token -- for them this is not an error.
	const auto host = ofquack::HostOf(config.endpoint);

	if (config.auth == ofquack::AuthMode::BASIC) {
		// Basic with no username would go out as an empty credential and come
		// back as a 401, whose message is about checking the password. The real
		// mistake is almost always the mode: an instance behind single sign-on
		// has no password to give, and the secret needed PROVIDER browser.
		if (config.username.empty()) {
			throw InvalidInputException(
			    "The secret for %s has no USERNAME, so it cannot authenticate.\n"
			    "If this instance uses a username and password, add USERNAME and PASSWORD to the secret.\n"
			    "If it is behind single sign-on, recreate the secret with PROVIDER browser and run "
			    "SELECT * FROM ofquack_sso_login().",
			    host);
		}
		return;
	}

	if (!config.token.empty()) {
		return;
	}
	if (ofquack::TokenCache::Get().Lookup(host).Valid()) {
		return;
	}
	// Deliberately does not sign in here: a SELECT must never open a browser
	// window on its own.
	throw InvalidInputException("Not signed in to %s. Run:\n  SELECT * FROM ofquack_sso_login();\n"
	                            "or set TOKEN on the secret if you obtained one another way.",
	                            host);
}

ofquack::FusionConfig ResolveFusionConfig(ClientContext &context, const named_parameter_map_t &named_parameters,
                                          FusionScanOptions &options) {
	const auto secret_name = NamedString(named_parameters, "secret");
	const auto endpoint_override = NamedString(named_parameters, "endpoint");

	unique_ptr<SecretEntry> entry;
	if (!secret_name.empty()) {
		entry = LookupByName(context, secret_name);
	} else if (!endpoint_override.empty()) {
		// A scoped secret is optional here: endpoint plus username and password
		// as named parameters is a complete configuration on its own.
		entry = LookupByEndpoint(context, endpoint_override);
	} else {
		entry = LookupSoleSecret(context);
	}

	ofquack::FusionConfig config;
	if (entry) {
		const auto &secret = AsFusionSecret(*entry, entry->secret->GetName());
		config.endpoint = SecretString(secret, "endpoint");
		config.report_path = SecretString(secret, "report_path");
		config.username = SecretString(secret, "username");
		config.password = SecretString(secret, "password");

		config.token = SecretString(secret, "token");
		// A secret created by the browser provider carries no password, so the
		// mode follows from what it holds when AUTH is not spelled out.
		auto auth = StringUtil::Lower(SecretString(secret, "auth"));
		if (auth.empty()) {
			auth = entry->secret->GetProvider() == "browser" || !config.token.empty() ? "bearer" : "basic";
		}
		if (auth == "bearer" || auth == "browser") {
			config.auth = ofquack::AuthMode::BEARER;
		} else if (auth == "basic") {
			config.auth = ofquack::AuthMode::BASIC;
		} else {
			throw BinderException("Unknown AUTH '%s' in secret '%s'; expected 'basic', 'bearer' or 'browser'", auth,
			                      entry->secret->GetName());
		}

		options.sso.login_url = SecretString(secret, "sso_login_url");
		options.sso.chrome_path = SecretString(secret, "chrome_path");
		options.sso.profile_dir = SecretString(secret, "chrome_profile_dir");
		const auto use_temp_profile = secret.TryGetValue("use_temp_profile");
		if (!use_temp_profile.IsNull()) {
			options.sso.use_temp_profile = use_temp_profile.GetValue<bool>();
		}
		const auto sso_timeout = secret.TryGetValue("sso_timeout_seconds");
		if (!sso_timeout.IsNull()) {
			options.sso.timeout_seconds = sso_timeout.GetValue<int64_t>();
		}

		const auto connect_timeout = secret.TryGetValue("connect_timeout");
		if (!connect_timeout.IsNull()) {
			config.connect_timeout_seconds = connect_timeout.GetValue<uint64_t>();
		}
		const auto read_timeout = secret.TryGetValue("read_timeout");
		if (!read_timeout.IsNull()) {
			config.read_timeout_seconds = read_timeout.GetValue<uint64_t>();
		}

		const auto secret_fetch_size = secret.TryGetValue("fetch_size");
		if (!secret_fetch_size.IsNull()) {
			options.fetch_size = secret_fetch_size.GetValue<idx_t>();
		}
		const auto secret_secured_views = secret.TryGetValue("secured_views");
		if (!secret_secured_views.IsNull()) {
			options.secured_views = secret_secured_views.GetValue<bool>();
		}
	}

	// Named parameters win over the secret: they are the more specific request.
	if (!endpoint_override.empty()) {
		config.endpoint = endpoint_override;
	}
	const auto report_path_override = NamedString(named_parameters, "report_path");
	if (!report_path_override.empty()) {
		config.report_path = report_path_override;
	}
	const auto username_override = NamedString(named_parameters, "username");
	if (!username_override.empty()) {
		config.username = username_override;
	}
	const auto password_override = NamedString(named_parameters, "password");
	if (!password_override.empty()) {
		config.password = password_override;
	}
	const auto fetch_size_override = NamedParameter(named_parameters, "fetch_size");
	if (!fetch_size_override.IsNull()) {
		options.fetch_size = fetch_size_override.GetValue<idx_t>();
	}
	const auto secured_views_override = NamedParameter(named_parameters, "secured_views");
	if (!secured_views_override.IsNull()) {
		options.secured_views = secured_views_override.GetValue<bool>();
	}
	const auto all_varchar_override = NamedParameter(named_parameters, "all_varchar");
	if (!all_varchar_override.IsNull()) {
		options.all_varchar = all_varchar_override.GetValue<bool>();
	}

	if (config.endpoint.empty()) {
		throw BinderException("No ENDPOINT: set it on the secret or pass endpoint := 'https://<your-fusion-host>'");
	}
	// Done before the endpoint is used as a cache key or a throttle key, so
	// that naming the host and naming the full service URL are one connection
	// rather than two.
	config.endpoint = ofquack::NormalizeFusionEndpoint(config.endpoint);
	if (config.report_path.empty()) {
		throw BinderException("No REPORT_PATH: set it on the secret or pass "
		                      "report_path := '/Custom/Financials/RP_ARB.xdo'");
	}

	// fetch_size 0 means "one request, no paging", so only the upper bound and
	// the non-zero lower bound are checked.
	if (options.fetch_size != 0 && (options.fetch_size < MIN_FETCH_SIZE || options.fetch_size > MAX_FETCH_SIZE)) {
		throw BinderException("fetch_size must be 0 (no paging) or between %llu and %llu, not %llu",
		                      static_cast<uint64_t>(MIN_FETCH_SIZE), static_cast<uint64_t>(MAX_FETCH_SIZE),
		                      static_cast<uint64_t>(options.fetch_size));
	}
	return config;
}

} // namespace duckdb
