#include "ofquack/metadata_functions.hpp"

#include "duckdb/function/table_function.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "ofquack/errors.hpp"
#include "ofquack/fusion_connection.hpp"
#include "ofquack/metadata_cache.hpp"
#include "ofquack/metadata_fetch.hpp"
#include "ofquack/oracle_type_map.hpp"
#include "ofquack/transport.hpp"

#include <memory>

namespace duckdb {

namespace {

//! Default lifetime of a cached row: a week. Fusion's dictionary changes when
//! someone deploys, not continuously, and a stale name costs one puzzled look
//! whereas refetching costs minutes.
constexpr int64_t DEFAULT_TTL_SECONDS = 7 * 24 * 60 * 60;

//! Metadata results are small and are produced in one go, so the scan is just
//! a cursor over rows that bind already assembled.
struct MaterialisedBindData : public TableFunctionData {
	vector<vector<Value>> rows;
};

struct MaterialisedState : public GlobalTableFunctionState {
	idx_t offset = 0;

	idx_t MaxThreads() const override {
		return 1;
	}
};

unique_ptr<GlobalTableFunctionState> InitMaterialised(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<MaterialisedState>();
}

void ScanMaterialised(ClientContext &, TableFunctionInput &data, DataChunk &output) {
	auto &bind_data = data.bind_data->Cast<MaterialisedBindData>();
	auto &state = data.global_state->Cast<MaterialisedState>();

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

ofquack::RequestContext ContextFor(ClientContext &context) {
	ofquack::RequestContext request_context;
	request_context.is_cancelled = [&context]() { return context.interrupted.load(); };
	return request_context;
}

//! Same translation as the query function: a bare "Invalid Error" says nothing
//! about which of the query, the credentials or the network to look at.
template <typename Callable>
auto WithTranslatedErrors(Callable &&callable) -> decltype(callable()) {
	try {
		return callable();
	} catch (const ofquack::CancelledError &) {
		throw InterruptException();
	} catch (const ofquack::AuthenticationError &auth_error) {
		throw InvalidInputException("%s", auth_error.what());
	} catch (const ofquack::FusionError &fusion_error) {
		throw IOException("%s", fusion_error.what());
	}
}

bool WantsRefresh(const named_parameter_map_t &named_parameters) {
	const auto entry = named_parameters.find("refresh");
	return entry != named_parameters.end() && !entry->second.IsNull() && entry->second.GetValue<bool>();
}

int64_t TtlFor(const named_parameter_map_t &named_parameters) {
	const auto entry = named_parameters.find("cache_ttl_seconds");
	if (entry == named_parameters.end() || entry->second.IsNull()) {
		return DEFAULT_TTL_SECONDS;
	}
	return entry->second.GetValue<int64_t>();
}

// ---------------------------------------------------------------------------
// oracle_fusion_tables
// ---------------------------------------------------------------------------

unique_ptr<FunctionData> TablesBind(ClientContext &context, TableFunctionBindInput &input,
                                    vector<LogicalType> &return_types, vector<string> &names) {
	FusionScanOptions options;
	auto config = ResolveFusionConfig(context, input.named_parameters, options);
	RequireUsableCredentials(config);
	const auto endpoint_key = EndpointKey(config.endpoint, config.report_path);

	std::vector<ofquack::TableInfo> tables;
	auto &cache = MetadataCache::Get();
	const bool refresh = WantsRefresh(input.named_parameters);
	if (refresh || !cache.TryGetTables(endpoint_key, TtlFor(input.named_parameters), tables)) {
		tables.clear();
		// Listing the dictionary is one of the most expensive calls there is,
		// so the result is written back before it is returned.
		auto transport = ofquack::CreateTransport(config);
		tables = WithTranslatedErrors(
		    [&]() { return ofquack::FetchTables(*transport, ContextFor(context), {"TABLE", "VIEW"}); });
		cache.PutTables(endpoint_key, tables);
	}

	auto bind_data = make_uniq<MaterialisedBindData>();
	for (const auto &table : tables) {
		bind_data->rows.push_back({Value(table.name), Value(table.type), Value(table.remarks), Value(table.table_id)});
	}

	names = {"table_name", "table_type", "remarks", "table_id"};
	return_types = {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR};
	return std::move(bind_data);
}

// ---------------------------------------------------------------------------
// oracle_fusion_columns
// ---------------------------------------------------------------------------

LogicalType DictionaryLogicalType(const ofquack::ColumnInfo &column) {
	const auto mapped = ofquack::MapOracleType(column.type_name, column.precision, column.scale);
	if (!mapped.known) {
		return LogicalType::VARCHAR;
	}
	switch (mapped.type) {
	case ofquack::InferredType::INTEGER:
		return LogicalType::INTEGER;
	case ofquack::InferredType::BIGINT:
		return LogicalType::BIGINT;
	case ofquack::InferredType::DECIMAL:
		return LogicalType::DECIMAL(38, mapped.scale);
	case ofquack::InferredType::TIMESTAMP:
		return LogicalType::TIMESTAMP;
	case ofquack::InferredType::DATE:
		return LogicalType::DATE;
	default:
		return LogicalType::VARCHAR;
	}
}

unique_ptr<FunctionData> ColumnsBind(ClientContext &context, TableFunctionBindInput &input,
                                     vector<LogicalType> &return_types, vector<string> &names) {
	const auto table_name = input.inputs[0].GetValue<string>();
	if (table_name.empty()) {
		throw BinderException("oracle_fusion_columns requires a table name");
	}
	FusionScanOptions options;
	auto config = ResolveFusionConfig(context, input.named_parameters, options);
	RequireUsableCredentials(config);
	const auto endpoint_key = EndpointKey(config.endpoint, config.report_path);

	auto &cache = MetadataCache::Get();
	std::vector<ofquack::ColumnInfo> columns;
	const bool refresh = WantsRefresh(input.named_parameters);
	if (refresh || !cache.TryGetColumns(endpoint_key, table_name, TtlFor(input.named_parameters), columns)) {
		columns.clear();
		auto transport = ofquack::CreateTransport(config);
		const auto request_context = ContextFor(context);

		columns = WithTranslatedErrors([&]() -> std::vector<ofquack::ColumnInfo> {
			// Columns of a table are looked up by its FND id, which means the
			// table list is needed first; the list is itself cached, so this is
			// usually free.
			std::vector<ofquack::TableInfo> tables;
			if (!cache.TryGetTables(endpoint_key, TtlFor(input.named_parameters), tables)) {
				tables = ofquack::FetchTables(*transport, request_context, {"TABLE", "VIEW"});
				cache.PutTables(endpoint_key, tables);
			}
			for (const auto &table : tables) {
				if (StringUtil::CIEquals(table.name, table_name)) {
					// Views are not in FND_COLUMNS at all.
					if (StringUtil::CIEquals(table.type, "VIEW") || table.table_id.empty()) {
						return ofquack::FetchColumnsOfView(*transport, request_context, table.name);
					}
					return ofquack::FetchColumnsOfTables(*transport, request_context, {table});
				}
			}
			throw BinderException("Oracle Fusion has no table or view named '%s'", table_name);
		});
		cache.PutColumns(endpoint_key, table_name, columns);
	}

	auto bind_data = make_uniq<MaterialisedBindData>();
	for (const auto &column : columns) {
		bind_data->rows.push_back({Value(column.name), Value(column.type_name),
		                           Value(DictionaryLogicalType(column).ToString()), Value::BIGINT(column.precision),
		                           Value::BIGINT(column.scale), Value::BIGINT(column.ordinal),
		                           Value::BOOLEAN(column.nullable), Value(column.remarks)});
	}

	names = {"column_name", "oracle_type", "duckdb_type", "precision", "scale", "ordinal", "nullable", "remarks"};
	return_types = {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::BIGINT,
	                LogicalType::BIGINT,  LogicalType::BIGINT,  LogicalType::BOOLEAN, LogicalType::VARCHAR};
	return std::move(bind_data);
}

// ---------------------------------------------------------------------------
// ofquack_cache_status / ofquack_cache_invalidate
// ---------------------------------------------------------------------------

const char *ModeName(CacheMode mode) {
	switch (mode) {
	case CacheMode::READ_WRITE:
		return "read_write";
	case CacheMode::READ_ONLY:
		return "read_only";
	default:
		return "memory";
	}
}

unique_ptr<FunctionData> CacheStatusBind(ClientContext &context, TableFunctionBindInput &input,
                                         vector<LogicalType> &return_types, vector<string> &names) {
	auto &cache = MetadataCache::Get();

	// The endpoint is optional here: without a secret the status still says
	// where the cache is and whether it can be written to.
	std::string endpoint_key;
	try {
		FusionScanOptions options;
		const auto config = ResolveFusionConfig(context, input.named_parameters, options);
		endpoint_key = EndpointKey(config.endpoint, config.report_path);
	} catch (const std::exception &) {
		endpoint_key.clear();
	}

	auto bind_data = make_uniq<MaterialisedBindData>();
	bind_data->rows.push_back({Value(ModeName(cache.Mode())),
	                           cache.Path().empty() ? Value(LogicalType::VARCHAR) : Value(cache.Path()),
	                           endpoint_key.empty() ? Value(LogicalType::VARCHAR) : Value(endpoint_key),
	                           Value::BIGINT(static_cast<int64_t>(cache.CountTables(endpoint_key))),
	                           Value::BIGINT(static_cast<int64_t>(cache.CountColumns(endpoint_key)))});

	names = {"mode", "path", "endpoint", "cached_tables", "cached_columns"};
	return_types = {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::BIGINT,
	                LogicalType::BIGINT};
	return std::move(bind_data);
}

unique_ptr<FunctionData> CacheInvalidateBind(ClientContext &context, TableFunctionBindInput &input,
                                             vector<LogicalType> &return_types, vector<string> &names) {
	FusionScanOptions options;
	const auto config = ResolveFusionConfig(context, input.named_parameters, options);
	const auto endpoint_key = EndpointKey(config.endpoint, config.report_path);

	std::string table_name;
	const auto table_parameter = input.named_parameters.find("table");
	if (table_parameter != input.named_parameters.end() && !table_parameter->second.IsNull()) {
		table_name = table_parameter->second.ToString();
	}

	auto &cache = MetadataCache::Get();
	const auto tables_before = cache.CountTables(endpoint_key);
	const auto columns_before = cache.CountColumns(endpoint_key);

	cache.InvalidateColumns(endpoint_key, table_name);
	if (table_name.empty()) {
		// Dropping the table list without its columns would leave columns that
		// can never be reached, since a column lookup starts from the list.
		cache.InvalidateTables(endpoint_key);
	}

	auto bind_data = make_uniq<MaterialisedBindData>();
	bind_data->rows.push_back(
	    {Value::BIGINT(static_cast<int64_t>(tables_before - cache.CountTables(endpoint_key))),
	     Value::BIGINT(static_cast<int64_t>(columns_before - cache.CountColumns(endpoint_key)))});

	names = {"tables_removed", "columns_removed"};
	return_types = {LogicalType::BIGINT, LogicalType::BIGINT};
	return std::move(bind_data);
}

} // namespace

void RegisterFusionMetadataFunctions(ExtensionLoader &loader) {
	TableFunction tables("oracle_fusion_tables", {}, ScanMaterialised, TablesBind, InitMaterialised);
	AddFusionNamedParameters(tables);
	tables.named_parameters["refresh"] = LogicalType::BOOLEAN;
	tables.named_parameters["cache_ttl_seconds"] = LogicalType::BIGINT;
	loader.RegisterFunction(tables);

	TableFunction columns("oracle_fusion_columns", {LogicalType::VARCHAR}, ScanMaterialised, ColumnsBind,
	                      InitMaterialised);
	AddFusionNamedParameters(columns);
	columns.named_parameters["refresh"] = LogicalType::BOOLEAN;
	columns.named_parameters["cache_ttl_seconds"] = LogicalType::BIGINT;
	loader.RegisterFunction(columns);

	TableFunction status("ofquack_cache_status", {}, ScanMaterialised, CacheStatusBind, InitMaterialised);
	AddFusionNamedParameters(status);
	loader.RegisterFunction(status);

	TableFunction invalidate("ofquack_cache_invalidate", {}, ScanMaterialised, CacheInvalidateBind, InitMaterialised);
	AddFusionNamedParameters(invalidate);
	invalidate.named_parameters["table"] = LogicalType::VARCHAR;
	loader.RegisterFunction(invalidate);
}

} // namespace duckdb
