#include "ofquack/metadata_functions.hpp"

#include "duckdb/function/table_function.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "ofquack/errors.hpp"
#include "ofquack/fusion_connection.hpp"
#include "ofquack/metadata_cache.hpp"
#include "ofquack/metadata_fetch.hpp"
#include "ofquack/metadata_queries.hpp"
#include "ofquack/oracle_type_map.hpp"
#include "ofquack/transport.hpp"

#include <cstdint>
#include <map>
#include <memory>

namespace duckdb {

uint64_t MetadataPageSize(ClientContext &context, const named_parameter_map_t &named_parameters) {
	const auto entry = named_parameters.find("page_size");
	if (entry != named_parameters.end() && !entry->second.IsNull()) {
		return entry->second.GetValue<uint64_t>();
	}
	Value setting;
	if (context.TryGetCurrentSetting("fusion_scanner_metadata_page_size", setting) && !setting.IsNull()) {
		return setting.GetValue<uint64_t>();
	}
	return 0; // the built-in default
}

namespace {

//! Default lifetime of a cached row: a week. Fusion's dictionary changes when
//! someone deploys, not continuously, and a stale name costs one puzzled look
//! whereas refetching costs minutes.
constexpr int64_t DEFAULT_TTL_SECONDS = INT64_C(7) * 24 * 60 * 60;

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
	request_context.is_cancelled = [&context]() {
		return context.interrupted.load();
	};
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

std::vector<ofquack::TableInfo> LoadTables(ClientContext &context, MetadataCache &cache,
                                           const std::string &endpoint_key, ofquack::FusionTransport &transport,
                                           const ofquack::RequestContext &request_context, int64_t ttl_seconds,
                                           uint64_t page_size, bool refresh, bool *stored_out = nullptr,
                                           int64_t *expected_out = nullptr) {
	std::vector<ofquack::TableInfo> tables;
	if (!refresh && cache.TryGetTables(endpoint_key, ttl_seconds, tables)) {
		if (stored_out) {
			*stored_out = true;
		}
		return tables;
	}

	auto population = cache.PopulationMutex("tables:" + endpoint_key);
	std::lock_guard<std::mutex> population_guard(*population);
	tables.clear();
	// The first cold caller may have filled the cache while this one waited.
	if (!refresh && cache.TryGetTables(endpoint_key, ttl_seconds, tables)) {
		if (stored_out) {
			*stored_out = true;
		}
		return tables;
	}

	int64_t expected = -1;
	tables = WithTranslatedErrors(
	    [&]() { return ofquack::FetchTables(transport, request_context, {"TABLE", "VIEW"}, page_size, &expected); });
	const auto stored = cache.PutTables(endpoint_key, tables, expected);
	if (stored_out) {
		*stored_out = stored;
	}
	// The caller has to be able to tell "the instance would not count its own
	// dictionary" from "the cache file would not take the rows": the first is a
	// permission or a refusal on the Fusion side, the second is local.
	if (expected_out) {
		*expected_out = expected;
	}
	(void)context;
	return tables;
}

// ---------------------------------------------------------------------------
// oracle_fusion_tables
// ---------------------------------------------------------------------------

unique_ptr<FunctionData> TablesBind(ClientContext &context, TableFunctionBindInput &input,
                                    vector<LogicalType> &return_types, vector<string> &names) {
	FusionScanOptions options;
	auto config = ResolveFusionConfig(context, input.named_parameters, options);
	RequireUsableCredentials(config);
	const auto endpoint_key = EndpointKey(config);

	auto &cache = MetadataCache::Get();
	const bool refresh = WantsRefresh(input.named_parameters);
	auto transport = ofquack::CreateTransport(config);
	const auto request_context = ContextFor(context);
	auto tables = LoadTables(context, cache, endpoint_key, *transport, request_context, TtlFor(input.named_parameters),
	                         MetadataPageSize(context, input.named_parameters), refresh);

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
	case ofquack::InferredType::DOUBLE:
		return LogicalType::DOUBLE;
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
	const auto endpoint_key = EndpointKey(config);

	auto &cache = MetadataCache::Get();
	std::vector<ofquack::ColumnInfo> columns;
	const bool refresh = WantsRefresh(input.named_parameters);
	const auto ttl = TtlFor(input.named_parameters);
	if (refresh || !cache.TryGetColumns(endpoint_key, table_name, ttl, columns)) {
		auto population = cache.PopulationMutex("columns:" + endpoint_key + ":" + StringUtil::Upper(table_name));
		std::lock_guard<std::mutex> population_guard(*population);
		columns.clear();
		if (refresh || !cache.TryGetColumns(endpoint_key, table_name, ttl, columns)) {
			auto transport = ofquack::CreateTransport(config);
			const auto request_context = ContextFor(context);

			columns = WithTranslatedErrors([&]() -> std::vector<ofquack::ColumnInfo> {
				// Columns of a table are looked up by its FND id, which means the
				// table list is needed first; the list is itself cached, so this is
				// usually free.
				auto tables = LoadTables(context, cache, endpoint_key, *transport, request_context, ttl,
				                         MetadataPageSize(context, input.named_parameters), refresh);
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
// fusion_scanner_cache_warm
// ---------------------------------------------------------------------------

//! Case-insensitive LIKE with % and _, enough for a table-name filter.
bool MatchesPattern(const std::string &name, const std::string &pattern) {
	if (pattern.empty() || pattern == "%") {
		return true;
	}
	const auto text = StringUtil::Upper(name);
	const auto glob = StringUtil::Upper(pattern);
	enum class TokenKind { LITERAL, ONE, MANY };
	struct Token {
		TokenKind kind;
		char literal = 0;
	};
	std::vector<Token> tokens;
	for (size_t index = 0; index < glob.size(); index++) {
		if (glob[index] == '\\' && index + 1 < glob.size()) {
			tokens.push_back({TokenKind::LITERAL, glob[++index]});
		} else if (glob[index] == '%') {
			tokens.push_back({TokenKind::MANY, 0});
		} else if (glob[index] == '_') {
			tokens.push_back({TokenKind::ONE, 0});
		} else {
			tokens.push_back({TokenKind::LITERAL, glob[index]});
		}
	}

	// Iterative backtracking, so a pattern of several wildcards cannot recurse
	// its way through a dictionary of thousands of names.
	size_t t = 0, g = 0, star = std::string::npos, matched = 0;
	while (t < text.size()) {
		if (g < tokens.size() && (tokens[g].kind == TokenKind::ONE ||
		                          (tokens[g].kind == TokenKind::LITERAL && tokens[g].literal == text[t]))) {
			t++;
			g++;
		} else if (g < tokens.size() && tokens[g].kind == TokenKind::MANY) {
			star = g++;
			matched = t;
		} else if (star != std::string::npos) {
			g = star + 1;
			t = ++matched;
		} else {
			return false;
		}
	}
	while (g < tokens.size() && tokens[g].kind == TokenKind::MANY) {
		g++;
	}
	return g == tokens.size();
}

//! Fetches the columns of many tables at once, so a catalog browser has
//! something to show.
//!
//! An attached catalog only lists tables whose columns it already knows --
//! offering a name it might then fail to describe is an internal error in
//! DuckDB, not a warning. This is how that knowledge is acquired deliberately,
//! in batches, rather than one slow table at a time or all thirty thousand of
//! them at once.
unique_ptr<FunctionData> CacheWarmBind(ClientContext &context, TableFunctionBindInput &input,
                                       vector<LogicalType> &return_types, vector<string> &names) {
	FusionScanOptions options;
	auto config = ResolveFusionConfig(context, input.named_parameters, options);
	RequireUsableCredentials(config);
	const auto endpoint_key = EndpointKey(config);

	const auto pattern_parameter = input.named_parameters.find("pattern");
	if (pattern_parameter == input.named_parameters.end() || pattern_parameter->second.IsNull() ||
	    pattern_parameter->second.ToString().empty()) {
		throw BinderException("pattern is required; name the table family to prefetch, for example pattern := 'AP\\_%%'. "
		                      "Use pattern := '%%' explicitly only when a broad warm is intentional");
	}
	const auto pattern = pattern_parameter->second.ToString();
	// Bounded by default: Fusion's dictionary runs to tens of thousands of
	// tables, and warming all of them is hours of SOAP calls.
	int64_t limit = 200;
	const auto limit_parameter = input.named_parameters.find("max_tables");
	if (limit_parameter != input.named_parameters.end() && !limit_parameter->second.IsNull()) {
		limit = limit_parameter->second.GetValue<int64_t>();
	}
	if (limit < 0) {
		throw BinderException("max_tables must be zero (no limit) or positive, not %lld", limit);
	}

	auto &cache = MetadataCache::Get();
	if (cache.Mode() == CacheMode::READ_ONLY) {
		throw IOException("The Oracle Fusion metadata cache is read-only, so it cannot be warmed. Close the process "
		                  "that holds %s and try again",
		                  cache.Path());
	}
	auto warm_population = cache.PopulationMutex("warm:" + endpoint_key);
	std::lock_guard<std::mutex> warm_guard(*warm_population);
	auto transport = ofquack::CreateTransport(config);
	const auto request_context = ContextFor(context);

	const auto ttl = TtlFor(input.named_parameters);
	bool tables_stored = false;
	int64_t tables_expected = -1;
	auto tables = LoadTables(context, cache, endpoint_key, *transport, request_context, ttl,
	                         MetadataPageSize(context, input.named_parameters), false, &tables_stored,
	                         &tables_expected);
	if (!tables_stored) {
		// Warming columns is only useful against a stored table list -- the
		// catalog lists from the cache and never from the network -- so this stops
		// rather than spending hours on rows nothing will read back. Which of the
		// two reasons it was decides what the user has to fix, so say which.
		if (tables_expected < 0) {
			throw IOException(
			    "Oracle Fusion listed its dictionary but would not count it, so the list cannot be checked for "
			    "completeness and is not cached -- and warming columns against a list that is not stored would "
			    "leave them unreachable.\nThe count is SELECT COUNT(DISTINCT UPPER(table_name)) over FND_VIEWS and "
			    "FND_TABLES; the account running this has to be able to read both. Run\n"
			    "  SELECT * FROM oracle_fusion_query('SELECT COUNT(*) FROM FND_TABLES')\n"
			    "to see what it is refused with.");
		}
		throw IOException("Oracle Fusion returned its dictionary, but the metadata cache at %s could not store it",
		                  cache.Path().empty() ? std::string("memory") : cache.Path());
	}

	std::vector<ofquack::TableInfo> wanted;
	int64_t skipped_known = 0;
	for (const auto &table : tables) {
		if (!MatchesPattern(table.name, pattern)) {
			continue;
		}
		std::vector<ofquack::ColumnInfo> already;
		if (cache.TryGetColumns(endpoint_key, table.name, ttl, already)) {
			skipped_known++;
			continue;
		}
		if (limit > 0 && static_cast<int64_t>(wanted.size()) >= limit) {
			break;
		}
		wanted.push_back(table);
	}

	int64_t warmed = 0;
	int64_t columns_written = 0;
	int64_t failed = 0;

	// Views are not in FND_COLUMNS and are fetched one at a time; tables go in
	// batches, which is where nearly all of the saving is.
	std::vector<ofquack::TableInfo> batchable;
	std::string first_error;

	// Views are written in batches rather than one at a time -- a transaction per
	// table was most of the local cost -- but never held back to the end of the
	// run. A view costs a request of its own, so a warm that reaches its last one
	// has spent hundreds of them; losing all of that to a retryable error or a
	// Ctrl-C at the tail is worse than the transactions ever were. Whatever has
	// arrived is flushed on the way out, and the retry skips it as already_cached.
	std::vector<std::pair<std::string, std::vector<ofquack::ColumnInfo>>> view_updates;
	auto flush_views = [&]() {
		if (view_updates.empty()) {
			return true;
		}
		const bool stored = cache.PutColumnsBatch(endpoint_key, view_updates);
		view_updates.clear();
		return stored;
	};

	try {
		for (const auto &table : wanted) {
			if (StringUtil::CIEquals(table.type, "VIEW") || table.table_id.empty()) {
				try {
					auto columns = ofquack::FetchColumnsOfView(*transport, request_context, table.name);
					columns_written += static_cast<int64_t>(columns.size());
					warmed += columns.empty() ? 0 : 1;
					failed += columns.empty() ? 1 : 0;
					view_updates.emplace_back(table.name, std::move(columns));
				} catch (const ofquack::CancelledError &) {
					throw InterruptException();
				} catch (const ofquack::AuthenticationError &error) {
					throw InvalidInputException("%s", error.what());
				} catch (const ofquack::RetryableError &error) {
					throw IOException("%s", error.what());
				} catch (const ofquack::TokenExpiredError &error) {
					throw IOException("%s", error.what());
				} catch (const ofquack::CircuitOpenError &error) {
					throw IOException("%s", error.what());
				} catch (const ofquack::FusionError &error) {
					// One unreadable object must not abandon the rest of the warm.
					failed++;
					if (first_error.empty()) {
						first_error = table.name + ": " + error.what();
					}
				}
				if (view_updates.size() >= ofquack::metadata::COLUMN_BATCH_SIZE && !flush_views()) {
					throw IOException("Oracle Fusion returned view metadata, but the metadata cache could not store it");
				}
				continue;
			}
			batchable.push_back(table);
		}
	} catch (...) {
		// Keep what this run already paid for. PutColumnsBatch reports a failure
		// rather than throwing, so nothing here can replace the exception on its
		// way out.
		flush_views();
		throw;
	}
	if (!flush_views()) {
		throw IOException("Oracle Fusion returned view metadata, but the metadata cache could not store it");
	}

	for (size_t start = 0; start < batchable.size(); start += ofquack::metadata::COLUMN_BATCH_SIZE) {
		const auto end = std::min(start + ofquack::metadata::COLUMN_BATCH_SIZE, batchable.size());
		const std::vector<ofquack::TableInfo> batch(batchable.begin() + static_cast<std::ptrdiff_t>(start),
		                                            batchable.begin() + static_cast<std::ptrdiff_t>(end));
		std::vector<ofquack::ColumnInfo> columns;
		try {
			columns = ofquack::FetchColumnsOfTables(*transport, request_context, batch);
		} catch (const ofquack::CancelledError &) {
			throw InterruptException();
		} catch (const ofquack::AuthenticationError &error) {
			throw InvalidInputException("%s", error.what());
		} catch (const ofquack::RetryableError &error) {
			throw IOException("%s", error.what());
		} catch (const ofquack::TokenExpiredError &error) {
			throw IOException("%s", error.what());
		} catch (const ofquack::CircuitOpenError &error) {
			throw IOException("%s", error.what());
		} catch (const ofquack::FusionError &error) {
			failed += static_cast<int64_t>(batch.size());
			if (first_error.empty()) {
				first_error = batch.front().name + "…: " + error.what();
			}
			continue;
		}

		// Split the batch's rows back out per table, so each is cached under
		// its own name -- including the ones that came back with nothing, which
		// is what stops them being offered to DuckDB later.
		std::map<std::string, std::vector<ofquack::ColumnInfo>> by_table;
		for (auto &column : columns) {
			by_table[StringUtil::Upper(column.table_name)].push_back(column);
		}
		std::vector<std::pair<std::string, std::vector<ofquack::ColumnInfo>>> batch_updates;
		for (const auto &table : batch) {
			auto found = by_table.find(StringUtil::Upper(table.name));
			if (found == by_table.end() || found->second.empty()) {
				failed++;
				batch_updates.emplace_back(table.name, std::vector<ofquack::ColumnInfo> {});
				continue;
			}
			columns_written += static_cast<int64_t>(found->second.size());
			warmed++;
			batch_updates.emplace_back(table.name, std::move(found->second));
		}
		if (!cache.PutColumnsBatch(endpoint_key, batch_updates)) {
			throw IOException("Oracle Fusion returned column metadata, but the metadata cache could not store it");
		}
	}

	auto bind_data = make_uniq<MaterialisedBindData>();
	bind_data->rows.push_back({Value::BIGINT(warmed), Value::BIGINT(columns_written), Value::BIGINT(failed),
	                           Value::BIGINT(skipped_known),
	                           first_error.empty() ? Value(LogicalType::VARCHAR) : Value(first_error)});
	names = {"tables_warmed", "columns_cached", "tables_without_columns", "already_cached", "first_error"};
	return_types = {LogicalType::BIGINT, LogicalType::BIGINT, LogicalType::BIGINT, LogicalType::BIGINT,
	                LogicalType::VARCHAR};
	return std::move(bind_data);
}

// ---------------------------------------------------------------------------
// fusion_scanner_cache_status / fusion_scanner_cache_invalidate
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
	std::string display_endpoint;
	std::string principal;
	try {
		FusionScanOptions options;
		const auto config = ResolveFusionConfig(context, input.named_parameters, options);
		display_endpoint = config.endpoint;
		principal = CachePrincipal(config);
		if (!principal.empty()) {
			endpoint_key = EndpointKey(config);
		}
	} catch (const std::exception &) {
		endpoint_key.clear();
		display_endpoint.clear();
		principal.clear();
	}

	const bool principal_known = !endpoint_key.empty();
	const auto cached_tables = principal_known ? static_cast<int64_t>(cache.CountTables(endpoint_key)) : 0;
	const auto fresh_tables = principal_known
	                              ? static_cast<int64_t>(cache.CountFreshTables(endpoint_key, DEFAULT_TTL_SECONDS))
	                              : 0;
	const auto expected = endpoint_key.empty() ? -1 : cache.ExpectedTables(endpoint_key);
	const auto counter = [principal_known](int64_t value) {
		return principal_known ? Value::BIGINT(value) : Value(LogicalType::BIGINT);
	};

	auto bind_data = make_uniq<MaterialisedBindData>();
	bind_data->rows.push_back(
	    {Value(ModeName(cache.Mode())), cache.Path().empty() ? Value(LogicalType::VARCHAR) : Value(cache.Path()),
	     display_endpoint.empty() ? Value(LogicalType::VARCHAR) : Value(display_endpoint), counter(cached_tables),
	     // -1 means the instance was never asked; that is
	     // unknown, not zero, and NULL says so.
	     expected < 0 ? Value(LogicalType::BIGINT) : Value::BIGINT(expected),
	     expected < 0 ? Value(LogicalType::BOOLEAN) : Value::BOOLEAN(fresh_tables >= expected),
	     counter(principal_known ? static_cast<int64_t>(cache.CountColumns(endpoint_key)) : 0), counter(fresh_tables),
	     counter(principal_known
	                 ? static_cast<int64_t>(cache.CountFreshColumns(endpoint_key, DEFAULT_TTL_SECONDS))
	                 : 0),
	     counter(principal_known
	                 ? static_cast<int64_t>(cache.CountFreshDescribedTables(endpoint_key, DEFAULT_TTL_SECONDS))
	                 : 0),
	     principal.empty() ? Value(LogicalType::VARCHAR) : Value(principal)});

	names = {"mode",           "path",          "endpoint",      "cached_tables", "dictionary_tables",
	         "complete",       "cached_columns", "fresh_tables", "fresh_columns", "described_tables",
	         "principal"};
	return_types = {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::BIGINT,
	                LogicalType::BIGINT,  LogicalType::BOOLEAN, LogicalType::BIGINT,  LogicalType::BIGINT,
	                LogicalType::BIGINT,  LogicalType::BIGINT,  LogicalType::VARCHAR};
	return std::move(bind_data);
}

unique_ptr<FunctionData> CacheInvalidateBind(ClientContext &context, TableFunctionBindInput &input,
                                             vector<LogicalType> &return_types, vector<string> &names) {
	FusionScanOptions options;
	const auto config = ResolveFusionConfig(context, input.named_parameters, options);
	const auto endpoint_key = EndpointKey(config);

	std::string table_name;
	const auto table_name_parameter = input.named_parameters.find("table_name");
	const auto legacy_table_parameter = input.named_parameters.find("table");
	if (table_name_parameter != input.named_parameters.end() && !table_name_parameter->second.IsNull()) {
		table_name = table_name_parameter->second.ToString();
	} else if (legacy_table_parameter != input.named_parameters.end() && !legacy_table_parameter->second.IsNull()) {
		table_name = legacy_table_parameter->second.ToString();
	}

	auto &cache = MetadataCache::Get();
	if (cache.Mode() == CacheMode::READ_ONLY) {
		throw IOException("The Oracle Fusion metadata cache is read-only, so it cannot be invalidated. Close the "
		                  "process that holds %s and try again",
		                  cache.Path());
	}
	const auto tables_before = cache.CountTables(endpoint_key);
	const auto columns_before = cache.CountColumns(endpoint_key);

	if (table_name.empty()) {
		// One transaction removes the list, its expected count, every column and
		// every ordering key, so no half-invalidated snapshot is observable.
		cache.InvalidateTables(endpoint_key);
	} else {
		cache.InvalidateColumns(endpoint_key, table_name);
	}

	auto bind_data = make_uniq<MaterialisedBindData>();
	bind_data->rows.push_back({Value::BIGINT(static_cast<int64_t>(tables_before - cache.CountTables(endpoint_key))),
	                           Value::BIGINT(static_cast<int64_t>(columns_before - cache.CountColumns(endpoint_key)))});

	names = {"tables_removed", "columns_removed"};
	return_types = {LogicalType::BIGINT, LogicalType::BIGINT};
	return std::move(bind_data);
}

} // namespace

void RegisterFusionMetadataFunctions(ExtensionLoader &loader) {
	DBConfig::GetConfig(loader.GetDatabaseInstance())
	    .AddExtensionOption("fusion_scanner_metadata_page_size",
	                        "Rows per page when listing Oracle Fusion's dictionary. Lower it if a listing "
	                        "keeps stopping short of the instance's own table count.",
	                        LogicalType::UBIGINT, Value::UBIGINT(ofquack::metadata::TABLE_LIST_PAGE_SIZE));

	TableFunction tables("oracle_fusion_tables", {}, ScanMaterialised, TablesBind, InitMaterialised);
	AddFusionNamedParameters(tables);
	tables.named_parameters["refresh"] = LogicalType::BOOLEAN;
	tables.named_parameters["cache_ttl_seconds"] = LogicalType::BIGINT;
	tables.named_parameters["page_size"] = LogicalType::UBIGINT;
	loader.RegisterFunction(tables);

	TableFunction columns("oracle_fusion_columns", {LogicalType::VARCHAR}, ScanMaterialised, ColumnsBind,
	                      InitMaterialised);
	AddFusionNamedParameters(columns);
	columns.named_parameters["refresh"] = LogicalType::BOOLEAN;
	columns.named_parameters["cache_ttl_seconds"] = LogicalType::BIGINT;
	loader.RegisterFunction(columns);

	TableFunction warm("fusion_scanner_cache_warm", {}, ScanMaterialised, CacheWarmBind, InitMaterialised);
	AddFusionNamedParameters(warm);
	warm.named_parameters["pattern"] = LogicalType::VARCHAR;
	warm.named_parameters["max_tables"] = LogicalType::BIGINT;
	warm.named_parameters["cache_ttl_seconds"] = LogicalType::BIGINT;
	warm.named_parameters["page_size"] = LogicalType::UBIGINT;
	loader.RegisterFunction(warm);

	TableFunction status("fusion_scanner_cache_status", {}, ScanMaterialised, CacheStatusBind, InitMaterialised);
	AddFusionNamedParameters(status);
	loader.RegisterFunction(status);

	TableFunction invalidate("fusion_scanner_cache_invalidate", {}, ScanMaterialised, CacheInvalidateBind,
	                         InitMaterialised);
	AddFusionNamedParameters(invalidate);
	invalidate.named_parameters["table"] = LogicalType::VARCHAR;
	invalidate.named_parameters["table_name"] = LogicalType::VARCHAR;
	loader.RegisterFunction(invalidate);
}

} // namespace duckdb
