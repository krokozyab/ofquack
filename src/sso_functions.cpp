#include "duckdb/function/table_function.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "ofquack/browser_auth.hpp"
#include "ofquack/errors.hpp"
#include "ofquack/fusion_connection.hpp"
#include "ofquack/host_throttle.hpp"
#include "ofquack/jwt.hpp"
#include "ofquack/sso_functions.hpp"
#include "ofquack/token_cache.hpp"

#include <chrono>
#include <mutex>

namespace duckdb {

namespace {

struct SsoBindData : public TableFunctionData {
	vector<vector<Value>> rows;
};

struct SsoState : public GlobalTableFunctionState {
	idx_t offset = 0;

	idx_t MaxThreads() const override {
		return 1;
	}
};

unique_ptr<GlobalTableFunctionState> InitSso(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<SsoState>();
}

void ScanSso(ClientContext &, TableFunctionInput &data, DataChunk &output) {
	auto &bind_data = data.bind_data->Cast<SsoBindData>();
	auto &state = data.global_state->Cast<SsoState>();

	if (state.offset >= bind_data.rows.size()) {
		output.SetCardinality(0);
		return;
	}
	const idx_t to_emit = MinValue<idx_t>(STANDARD_VECTOR_SIZE, bind_data.rows.size() - state.offset);
	output.SetCardinality(to_emit);
	for (idx_t row = 0; row < to_emit; row++) {
		const auto &values = bind_data.rows[state.offset + row];
		for (idx_t column = 0; column < values.size(); column++) {
			output.SetValue(column, row, values[column]);
		}
	}
	state.offset += to_emit;
}

//! One sign-in at a time, per host.
//!
//! Without this, several scans noticing an expired token at once would each
//! open their own browser window -- and the person would be asked to sign in
//! repeatedly for a single query.
std::mutex &SignInLock() {
	static std::mutex lock;
	return lock;
}

int64_t NowEpochSeconds() {
	return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

Value TimestampFromEpoch(int64_t epoch_seconds) {
	if (epoch_seconds <= 0) {
		return Value(LogicalType::TIMESTAMP);
	}
	return Value::TIMESTAMP(Timestamp::FromEpochSeconds(epoch_seconds));
}

unique_ptr<FunctionData> SsoLoginBind(ClientContext &context, TableFunctionBindInput &input,
                                      vector<LogicalType> &return_types, vector<string> &names) {
	FusionScanOptions options;
	auto config = ResolveFusionConfig(context, input.named_parameters, options);
	const auto host = ofquack::HostOf(config.endpoint);

	auto settings = options.sso;
	if (settings.login_url.empty()) {
		// Signing in happens on the Fusion application host, which is the same
		// host as the report endpoint.
		const auto scheme_end = config.endpoint.find("://");
		settings.login_url = (scheme_end == std::string::npos ? "https://" : config.endpoint.substr(0, scheme_end + 3)) +
		                     host;
	}

	std::lock_guard<std::mutex> guard(SignInLock());

	// Another query may have signed in while this one waited for the lock.
	const auto existing = ofquack::TokenCache::Get().Lookup(host);
	const bool force = [&]() {
		const auto entry = input.named_parameters.find("force");
		return entry != input.named_parameters.end() && !entry->second.IsNull() && entry->second.GetValue<bool>();
	}();
	if (!force && existing.Valid() && !ofquack::TokenCache::Get().ShouldRefresh(host)) {
		auto bind_data = make_uniq<SsoBindData>();
		bind_data->rows.push_back({Value(host),
		                           existing.subject.empty() ? Value(LogicalType::VARCHAR) : Value(existing.subject),
		                           TimestampFromEpoch(existing.expires_at_epoch), Value::BOOLEAN(false)});
		names = {"host", "subject", "expires_at", "signed_in"};
		return_types = {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::TIMESTAMP, LogicalType::BOOLEAN};
		return std::move(bind_data);
	}

	ofquack::BrowserAuthResult result;
	try {
		result = ofquack::AuthenticateThroughBrowser(settings);
	} catch (const ofquack::FusionError &error) {
		throw IOException("%s", error.what());
	}

	ofquack::TokenCache::Get().Store(host, result.access_token, result.refresh_token, result.expires_in_seconds);
	const auto stored = ofquack::TokenCache::Get().Lookup(host);

	auto bind_data = make_uniq<SsoBindData>();
	bind_data->rows.push_back({Value(host),
	                           stored.subject.empty() ? Value(LogicalType::VARCHAR) : Value(stored.subject),
	                           TimestampFromEpoch(stored.expires_at_epoch), Value::BOOLEAN(true)});

	names = {"host", "subject", "expires_at", "signed_in"};
	return_types = {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::TIMESTAMP, LogicalType::BOOLEAN};
	return std::move(bind_data);
}

unique_ptr<FunctionData> SsoStatusBind(ClientContext &context, TableFunctionBindInput &input,
                                       vector<LogicalType> &return_types, vector<string> &names) {
	auto bind_data = make_uniq<SsoBindData>();

	// Works without a secret: with one, it reports that host specifically.
	std::string host;
	try {
		FusionScanOptions options;
		const auto config = ResolveFusionConfig(context, input.named_parameters, options);
		host = ofquack::HostOf(config.endpoint);
	} catch (const std::exception &) {
		host.clear();
	}

	if (!host.empty()) {
		const auto token = ofquack::TokenCache::Get().Lookup(host);
		// Never the token itself: this is a view for a person, and printing a
		// live bearer token puts it into scrollback and query history.
		bind_data->rows.push_back({Value(host), Value::BOOLEAN(token.Valid()),
		                           token.subject.empty() ? Value(LogicalType::VARCHAR) : Value(token.subject),
		                           TimestampFromEpoch(token.expires_at_epoch),
		                           Value::BOOLEAN(ofquack::TokenCache::Get().ShouldRefresh(host)),
		                           Value::BIGINT(token.Valid() ? token.expires_at_epoch - NowEpochSeconds() : 0)});
	}

	names = {"host", "have_token", "subject", "expires_at", "should_refresh", "expires_in_seconds"};
	return_types = {LogicalType::VARCHAR, LogicalType::BOOLEAN, LogicalType::VARCHAR,
	                LogicalType::TIMESTAMP, LogicalType::BOOLEAN, LogicalType::BIGINT};
	return std::move(bind_data);
}

unique_ptr<FunctionData> SsoLogoutBind(ClientContext &context, TableFunctionBindInput &input,
                                       vector<LogicalType> &return_types, vector<string> &names) {
	FusionScanOptions options;
	const auto config = ResolveFusionConfig(context, input.named_parameters, options);
	const auto host = ofquack::HostOf(config.endpoint);

	const auto had_token = ofquack::TokenCache::Get().Lookup(host).Valid();
	ofquack::TokenCache::Get().Forget(host);

	auto bind_data = make_uniq<SsoBindData>();
	bind_data->rows.push_back({Value(host), Value::BOOLEAN(had_token)});
	names = {"host", "token_discarded"};
	return_types = {LogicalType::VARCHAR, LogicalType::BOOLEAN};
	return std::move(bind_data);
}

} // namespace

void RegisterFusionSsoFunctions(ExtensionLoader &loader) {
	// Sign-in is its own function rather than something a query does on demand:
	// it opens a browser window and waits for a person, which must never happen
	// unexpectedly in the middle of somebody's SELECT.
	TableFunction login("ofquack_sso_login", {}, ScanSso, SsoLoginBind, InitSso);
	AddFusionNamedParameters(login);
	login.named_parameters["force"] = LogicalType::BOOLEAN;
	loader.RegisterFunction(login);

	TableFunction status("ofquack_sso_status", {}, ScanSso, SsoStatusBind, InitSso);
	AddFusionNamedParameters(status);
	loader.RegisterFunction(status);

	TableFunction logout("ofquack_sso_logout", {}, ScanSso, SsoLogoutBind, InitSso);
	AddFusionNamedParameters(logout);
	loader.RegisterFunction(logout);
}

} // namespace duckdb
