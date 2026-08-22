#include "ofquack/fusion_connection.hpp"

#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/secret/secret_manager.hpp"

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

		const auto auth = StringUtil::Lower(SecretString(secret, "auth"));
		if (auth == "browser" || auth == "bearer") {
			throw NotImplementedException("AUTH '%s' is not implemented yet; use AUTH 'basic'", auth);
		}
		if (!auth.empty() && auth != "basic") {
			throw BinderException("Unknown AUTH '%s' in secret '%s'; expected 'basic'", auth,
			                      entry->secret->GetName());
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

	if (config.endpoint.empty()) {
		throw BinderException("No ENDPOINT: set it on the secret or pass endpoint := 'https://…/"
		                      "ExternalReportWSSService?WSDL'");
	}
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
