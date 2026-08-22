#include "ofquack/fusion_catalog.hpp"

#include "duckdb/catalog/catalog_entry/duck_schema_entry.hpp"
#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/catalog/default/default_generator.hpp"
#include "duckdb/catalog/duck_catalog.hpp"
#include "duckdb/main/attached_database.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/parser/parsed_data/attach_info.hpp"
#include "duckdb/parser/parsed_data/create_schema_info.hpp"
#include "duckdb/parser/parsed_data/create_table_info.hpp"
#include "duckdb/planner/bound_result_modifier.hpp"
#include "duckdb/planner/operator/logical_get.hpp"
#include "duckdb/planner/parsed_data/bound_create_table_info.hpp"
#include "duckdb/storage/storage_extension.hpp"
#include "duckdb/transaction/duck_transaction_manager.hpp"
#include "ofquack/errors.hpp"
#include "ofquack/fusion_connection.hpp"
#include "ofquack/fusion_filter.hpp"
#include "ofquack/metadata_cache.hpp"
#include "ofquack/metadata_fetch.hpp"
#include "ofquack/oracle_type_map.hpp"
#include "ofquack/sql_rewrite.hpp"
#include "ofquack/transport.hpp"
#include "ofquack/xml_report.hpp"

#include <memory>
#include <mutex>
#include <unordered_map>

namespace duckdb {

namespace {

constexpr const char *STORAGE_TYPE = "oracle_fusion";
constexpr int64_t CATALOG_CACHE_TTL_SECONDS = 7 * 24 * 60 * 60;

//! Everything one ATTACH knows, shared by the catalog, every table entry it
//! produces, and every scan those tables start.
//!
//! Metadata is cached here as well as on disk: a lookup that misses the
//! in-memory map still checks the file, and only then asks Fusion. The mutex is
//! not optional -- DefaultGenerator::LockDuringCreate() is false, so DuckDB may
//! materialise the same table on two threads at once.
struct FusionAttachedState {
	ofquack::FusionConfig config;
	FusionScanOptions options;
	string secret_name;
	string endpoint_key;
	std::shared_ptr<ofquack::FusionTransport> transport;

	std::mutex metadata_lock;
	bool tables_loaded = false;
	std::vector<ofquack::TableInfo> tables;
	std::unordered_map<string, std::vector<ofquack::ColumnInfo>> columns_by_table;

	ofquack::RequestContext RequestContextFor(ClientContext &context) {
		ofquack::RequestContext request_context;
		request_context.is_cancelled = [&context]() { return context.interrupted.load(); };
		return request_context;
	}

	//! The table list, from memory, then from the file, then from Fusion.
	const std::vector<ofquack::TableInfo> &Tables(ClientContext &context) {
		if (tables_loaded) {
			return tables;
		}
		auto &cache = MetadataCache::Get();
		if (!cache.TryGetTables(endpoint_key, CATALOG_CACHE_TTL_SECONDS, tables)) {
			tables.clear();
			tables = ofquack::FetchTables(*transport, RequestContextFor(context), {"TABLE", "VIEW"});
			cache.PutTables(endpoint_key, tables);
		}
		tables_loaded = true;
		return tables;
	}

	optional_ptr<const ofquack::TableInfo> FindTable(ClientContext &context, const string &name) {
		for (const auto &table : Tables(context)) {
			if (StringUtil::CIEquals(table.name, name)) {
				return &table;
			}
		}
		return nullptr;
	}

	const std::vector<ofquack::ColumnInfo> &Columns(ClientContext &context, const ofquack::TableInfo &table) {
		const auto key = StringUtil::Upper(table.name);
		const auto known = columns_by_table.find(key);
		if (known != columns_by_table.end()) {
			return known->second;
		}

		auto &cache = MetadataCache::Get();
		std::vector<ofquack::ColumnInfo> columns;
		if (!cache.TryGetColumns(endpoint_key, table.name, CATALOG_CACHE_TTL_SECONDS, columns)) {
			columns.clear();
			const auto request_context = RequestContextFor(context);
			// Views are not in FND_COLUMNS; tables are looked up by TABLE_ID.
			columns = StringUtil::CIEquals(table.type, "VIEW") || table.table_id.empty()
			              ? ofquack::FetchColumnsOfView(*transport, request_context, table.name)
			              : ofquack::FetchColumnsOfTables(*transport, request_context, {table});
			cache.PutColumns(endpoint_key, table.name, columns);
		}
		return columns_by_table.emplace(key, std::move(columns)).first->second;
	}
};

LogicalType TypeOf(const ofquack::ColumnInfo &column, bool &from_dictionary) {
	const auto mapped = ofquack::MapOracleType(column.type_name, column.precision, column.scale);
	from_dictionary = mapped.known;
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

// ---------------------------------------------------------------------------
// The scan
// ---------------------------------------------------------------------------

struct FusionCatalogScanBindData : public TableFunctionData {
	std::shared_ptr<FusionAttachedState> state;
	string object_name;
	vector<FusionColumn> columns;
	optional_ptr<TableCatalogEntry> table_entry;
};

struct FusionCatalogScanState : public GlobalTableFunctionState {
	//! Positions in `columns` that this scan actually reads, in output order.
	vector<column_t> projection;
	//! Column names as they appear in the statement, aligned with `projection`.
	vector<string> projected_names;
	vector<LogicalType> projected_types;
	string where_clause;
	//! Number of vectors the chunk carries. COUNT(*) reads no columns at all.
	idx_t chunk_columns = 0;

	string base_sql;
	ofquack::ParsedReport page;
	idx_t offset_in_page = 0;
	idx_t rows_emitted = 0;
	bool more_pages = false;
	bool paginate = false;

	idx_t MaxThreads() const override {
		return 1;
	}
};

[[noreturn]] void RethrowAsDatabaseError(const ofquack::FusionError &error, const string &sql) {
	throw IOException("%s\nSQL: %s", error.what(), sql);
}

ofquack::ParsedReport FetchCatalogPage(FusionCatalogScanBindData &bind_data, FusionCatalogScanState &state,
                                       ClientContext &context, idx_t offset) {
	const auto statement =
	    state.paginate ? ofquack::ApplyPagination(state.base_sql, offset, bind_data.state->options.fetch_size)
	                   : state.base_sql;
	ofquack::RequestContext request_context;
	request_context.is_cancelled = [&context]() { return context.interrupted.load(); };
	try {
		return ofquack::ParseRows(ofquack::ExtractReportXML(bind_data.state->transport->Execute(statement,
		                                                                                       request_context)));
	} catch (const ofquack::CancelledError &) {
		throw InterruptException();
	} catch (const ofquack::FusionError &error) {
		RethrowAsDatabaseError(error, statement);
	} catch (const std::runtime_error &error) {
		throw IOException("Could not read the Oracle Fusion report response: %s\nSQL: %s", error.what(), statement);
	}
}

unique_ptr<GlobalTableFunctionState> FusionCatalogScanInit(ClientContext &context, TableFunctionInitInput &input) {
	auto &bind_data = input.bind_data->CastNoConst<FusionCatalogScanBindData>();
	auto state = make_uniq<FusionCatalogScanState>();

	state->projection = input.column_ids;
	state->chunk_columns = state->projection.size();

	// A projection is not an optimisation here: every column that is selected
	// travels back as base64-encoded XML, so reading two columns of a hundred
	// is two orders of magnitude less data.
	auto selected = input.column_ids;
	if (selected.empty()) {
		// COUNT(*) reads nothing, but Oracle still needs a select list.
		selected.push_back(0);
	}
	string select_list;
	for (const auto column_index : selected) {
		if (column_index >= bind_data.columns.size()) {
			throw NotImplementedException("ofquack does not support virtual columns");
		}
		if (!select_list.empty()) {
			select_list += ", ";
		}
		const auto &column = bind_data.columns[column_index];
		select_list += KeywordHelper::WriteQuoted(column.name, '"');
		state->projected_names.push_back(column.name);
		state->projected_types.push_back(column.type);
	}

	if (input.filters) {
		state->where_clause = BuildOracleWhereClause(*input.filters, bind_data.columns, selected);
	}

	state->base_sql = "SELECT " + select_list + " FROM " + KeywordHelper::WriteQuoted(bind_data.object_name, '"');
	if (!state->where_clause.empty()) {
		state->base_sql += " WHERE " + state->where_clause;
	}
	state->paginate = ofquack::ClassifyForPagination(state->base_sql, bind_data.state->options.fetch_size) ==
	                  ofquack::PaginationVerdict::YES;

	state->page = FetchCatalogPage(bind_data, *state, context, 0);
	state->more_pages = state->paginate && state->page.rows.size() == bind_data.state->options.fetch_size;
	return std::move(state);
}

void FusionCatalogScan(ClientContext &context, TableFunctionInput &data, DataChunk &output) {
	auto &bind_data = data.bind_data->CastNoConst<FusionCatalogScanBindData>();
	auto &state = data.global_state->Cast<FusionCatalogScanState>();

	while (state.offset_in_page >= state.page.rows.size()) {
		if (!state.more_pages) {
			output.SetCardinality(0);
			return;
		}
		state.page = FetchCatalogPage(bind_data, state, context, state.rows_emitted);
		state.offset_in_page = 0;
		state.more_pages = state.page.rows.size() == bind_data.state->options.fetch_size;
	}

	const idx_t to_emit = MinValue<idx_t>(STANDARD_VECTOR_SIZE, state.page.rows.size() - state.offset_in_page);
	output.SetCardinality(to_emit);

	// COUNT(*) wants the cardinality and no vectors at all; writing one would
	// be writing past the chunk.
	for (idx_t column_index = 0; column_index < state.chunk_columns; column_index++) {
		auto &vector = output.data[column_index];
		auto &validity = FlatVector::Validity(vector);
		const auto &column_name = state.projected_names[column_index];
		const auto &type = state.projected_types[column_index];
		const bool as_varchar = type.id() == LogicalTypeId::VARCHAR;
		auto entries = as_varchar ? FlatVector::GetData<string_t>(vector) : nullptr;

		for (idx_t row_index = 0; row_index < to_emit; row_index++) {
			const auto &row = state.page.rows[state.offset_in_page + row_index];
			const auto entry = row.find(column_name);
			if (entry == row.end() || (!as_varchar && entry->second.empty())) {
				validity.SetInvalid(row_index);
				continue;
			}
			if (as_varchar) {
				entries[row_index] = StringVector::AddString(vector, entry->second);
				continue;
			}
			Value converted;
			string conversion_error;
			if (!Value(entry->second).DefaultTryCastAs(type, converted, &conversion_error)) {
				validity.SetInvalid(row_index);
				continue;
			}
			vector.SetValue(row_index, converted);
		}
	}
	state.offset_in_page += to_emit;
	state.rows_emitted += to_emit;
}

//! Without this DuckDB does not recognise the scan as reading a base table.
BindInfo FusionCatalogScanBindInfo(const optional_ptr<FunctionData> bind_data) {
	auto &bind = bind_data->CastNoConst<FusionCatalogScanBindData>();
	if (!bind.table_entry) {
		throw InternalException("an attached Oracle Fusion scan has no table entry");
	}
	return BindInfo(*bind.table_entry);
}

// ---------------------------------------------------------------------------
// Catalog entries
// ---------------------------------------------------------------------------

class FusionTableEntry : public TableCatalogEntry {
public:
	FusionTableEntry(Catalog &catalog, SchemaCatalogEntry &schema, CreateTableInfo &info,
	                 std::shared_ptr<FusionAttachedState> state_p, string object_name_p, vector<FusionColumn> columns_p)
	    : TableCatalogEntry(catalog, schema, info), state(std::move(state_p)), object_name(std::move(object_name_p)),
	      fusion_columns(std::move(columns_p)) {
	}

	//! Returns nullptr when Fusion has no such object.
	//!
	//! That is not an error: DuckDB asks every attached catalog about names
	//! that may belong to none of them, and a catalog that throws on an unknown
	//! name breaks those lookups.
	static unique_ptr<FusionTableEntry> Create(ClientContext &context, Catalog &catalog, SchemaCatalogEntry &schema,
	                                           const std::shared_ptr<FusionAttachedState> &state,
	                                           const string &object_name) {
		std::lock_guard<std::mutex> guard(state->metadata_lock);
		auto table = state->FindTable(context, object_name);
		if (!table) {
			return nullptr;
		}
		const auto &columns = state->Columns(context, *table);
		if (columns.empty()) {
			return nullptr;
		}

		auto info = make_uniq<CreateTableInfo>();
		info->schema = schema.name;
		info->table = table->name;
		vector<FusionColumn> fusion_columns;
		for (const auto &column : columns) {
			bool from_dictionary = false;
			auto type = TypeOf(column, from_dictionary);
			info->columns.AddColumn(ColumnDefinition(column.name, type));
			fusion_columns.push_back(FusionColumn {column.name, type, from_dictionary});
		}
		info->on_conflict = OnCreateConflict::IGNORE_ON_CONFLICT;
		return make_uniq<FusionTableEntry>(catalog, schema, *info, state, table->name, std::move(fusion_columns));
	}

	TableFunction GetScanFunction(ClientContext &context, unique_ptr<FunctionData> &bind_data) override {
		auto scan_bind = make_uniq<FusionCatalogScanBindData>();
		scan_bind->state = state;
		scan_bind->object_name = object_name;
		scan_bind->columns = fusion_columns;
		scan_bind->table_entry = this;
		bind_data = std::move(scan_bind);

		// No bind function: the bind data is supplied above, and the statement
		// cannot be written until init, which is where the projection and the
		// filters arrive. Nothing reaches Fusion during binding.
		TableFunction function({}, FusionCatalogScan, nullptr, FusionCatalogScanInit);
		function.name = "ofquack_attached_scan";
		function.get_bind_info = FusionCatalogScanBindInfo;
		function.projection_pushdown = true;

		Value pushdown;
		function.filter_pushdown =
		    context.TryGetCurrentSetting("ofquack_filter_pushdown", pushdown) && BooleanValue::Get(pushdown);
		return function;
	}

	TableStorageInfo GetStorageInfo(ClientContext &) override {
		return {};
	}

	//! A BI Publisher report has no row identifier, and the base class offers
	//! one by default. Left in place, DuckDB plans scans that ask for it and
	//! the scan is handed a column id it cannot map to anything.
	virtual_column_map_t GetVirtualColumns() const override {
		return {};
	}

	vector<column_t> GetRowIdColumns() const override {
		return {};
	}

	unique_ptr<BaseStatistics> GetStatistics(ClientContext &, column_t) override {
		return nullptr;
	}

	//! The base implementation throws InternalException, which marks the whole
	//! database invalid and kills the connection. DuckDB reaches for local
	//! storage on paths that assume a DuckDB-native table, so this must fail
	//! gracefully instead.
	DataTable &GetStorage() override {
		throw NotImplementedException("Oracle Fusion table \"%s\" has no local storage", object_name);
	}

	void OnDrop() override {
		throw NotImplementedException("Oracle Fusion table \"%s\" cannot be dropped: ofquack is read-only",
		                              object_name);
	}

private:
	std::shared_ptr<FusionAttachedState> state;
	string object_name;
	vector<FusionColumn> fusion_columns;
};

//! Materialises table entries on demand.
//!
//! CreateDefaultEntry is how `SELECT * FROM f.main.T` resolves, and it costs
//! the columns of one table. GetDefaultEntries is the expensive one -- it lists
//! the whole schema -- and DuckDB only calls it for SHOW TABLES, duckdb_tables()
//! and completion, once per catalog.
class FusionTableGenerator : public DefaultGenerator {
public:
	FusionTableGenerator(Catalog &catalog, SchemaCatalogEntry &schema_p, std::shared_ptr<FusionAttachedState> state_p)
	    : DefaultGenerator(catalog), schema(schema_p), state(std::move(state_p)) {
	}

	vector<string> GetDefaultEntries() override {
		// Called without a ClientContext, so this can only answer from what is
		// already known; a cold catalog reports nothing rather than blocking
		// SHOW TABLES on a multi-second dictionary read.
		std::lock_guard<std::mutex> guard(state->metadata_lock);
		vector<string> names;
		if (!state->tables_loaded) {
			std::vector<ofquack::TableInfo> cached;
			if (MetadataCache::Get().TryGetTables(state->endpoint_key, CATALOG_CACHE_TTL_SECONDS, cached)) {
				state->tables = std::move(cached);
				state->tables_loaded = true;
			}
		}
		for (const auto &table : state->tables) {
			names.push_back(table.name);
		}
		return names;
	}

	unique_ptr<CatalogEntry> CreateDefaultEntry(ClientContext &context, const string &entry_name) override {
		return FusionTableEntry::Create(context, catalog, schema, state, entry_name);
	}

private:
	SchemaCatalogEntry &schema;
	std::shared_ptr<FusionAttachedState> state;
};

class FusionCatalog : public DuckCatalog {
public:
	FusionCatalog(AttachedDatabase &db, std::shared_ptr<FusionAttachedState> state_p)
	    : DuckCatalog(db), state(std::move(state_p)) {
	}

	string GetCatalogType() override {
		return STORAGE_TYPE;
	}

	//! Deliberately does not talk to Fusion. The schema is fixed, so an ATTACH
	//! costs nothing; the first question about a table is what pays.
	void Initialize(bool load_builtin) override {
		DuckCatalog::Initialize(load_builtin);
		auto transaction = CatalogTransaction::GetSystemTransaction(GetAttached().GetDatabase());
		auto &schema = GetSchema(transaction, DEFAULT_SCHEMA).Cast<DuckSchemaEntry>();
		schema.GetCatalogSet(CatalogType::TABLE_ENTRY)
		    .SetDefaultGenerator(make_uniq<FusionTableGenerator>(*this, schema, state));
	}

	optional_ptr<CatalogEntry> CreateSchema(CatalogTransaction transaction, CreateSchemaInfo &info) override {
		// DuckCatalog::Initialize creates `main` through this very method, so
		// refusing unconditionally would refuse our own construction.
		if (info.schema == DEFAULT_SCHEMA) {
			return DuckCatalog::CreateSchema(transaction, info);
		}
		throw NotImplementedException("ofquack exposes a single schema and cannot create another");
	}

	void DropSchema(ClientContext &, DropInfo &) override {
		throw NotImplementedException("ofquack is read-only: schemas cannot be dropped");
	}

	//! CREATE TABLE does not go through PlanCreateTableAs, so without this a
	//! plain CREATE TABLE would quietly succeed -- making a DuckDB-local table
	//! inside a catalog that is supposed to be a window onto Fusion, which
	//! would then shadow a real Fusion table of the same name.
	ErrorData SupportsCreateTable(BoundCreateTableInfo &) override {
		return ErrorData(ExceptionType::NOT_IMPLEMENTED,
		                 "ofquack is read-only: tables cannot be created in an attached Oracle Fusion catalog");
	}

	PhysicalOperator &PlanInsert(ClientContext &, PhysicalPlanGenerator &, LogicalInsert &,
	                             optional_ptr<PhysicalOperator>) override {
		throw NotImplementedException("ofquack is read-only: Oracle Fusion cannot be written through BI Publisher");
	}

	PhysicalOperator &PlanDelete(ClientContext &, PhysicalPlanGenerator &, LogicalDelete &,
	                             PhysicalOperator &) override {
		throw NotImplementedException("ofquack is read-only: Oracle Fusion cannot be written through BI Publisher");
	}

	PhysicalOperator &PlanUpdate(ClientContext &, PhysicalPlanGenerator &, LogicalUpdate &,
	                             PhysicalOperator &) override {
		throw NotImplementedException("ofquack is read-only: Oracle Fusion cannot be written through BI Publisher");
	}

	PhysicalOperator &PlanCreateTableAs(ClientContext &, PhysicalPlanGenerator &, LogicalCreateTable &,
	                                    PhysicalOperator &) override {
		throw NotImplementedException("ofquack is read-only: tables cannot be created in Oracle Fusion");
	}

private:
	std::shared_ptr<FusionAttachedState> state;
};

// ---------------------------------------------------------------------------
// ATTACH
// ---------------------------------------------------------------------------

unique_ptr<Catalog> FusionAttach(optional_ptr<StorageExtensionInfo>, ClientContext &context, AttachedDatabase &db,
                                 const string &, AttachInfo &info, AttachOptions &options) {
	auto state = std::make_shared<FusionAttachedState>();

	// The named parameters of the query function are reused here, so ATTACH
	// accepts the same spellings; the secret may come from the path or from a
	// SECRET option.
	named_parameter_map_t parameters;
	for (const auto &option : info.options) {
		const auto key = StringUtil::Lower(option.first);
		if (key == "type" || key == "read_only" || key == "readonly") {
			continue;
		}
		parameters[key] = option.second;
	}
	if (!info.path.empty() && parameters.find("secret") == parameters.end()) {
		parameters["secret"] = Value(info.path);
	}

	state->config = ResolveFusionConfig(context, parameters, state->options);
	state->endpoint_key = EndpointKey(state->config.endpoint, state->config.report_path);
	state->transport = ofquack::CreateTransport(state->config);

	// DuckDB builds a local StorageManager for a DuckCatalog from info.path,
	// and our path is a secret name rather than a file.
	//
	// The access mode is deliberately left alone. Marking the attachment
	// READ_ONLY would be the tidier contract, but DuckDB refuses to open an
	// in-memory database read-only, and the storage it opens here is the local
	// one. Read-only is therefore enforced by the catalog itself: every DDL and
	// DML entry point below throws. That covers the paths DuckDB's own
	// modified_databases check would have caught, and the internal ones it
	// would not.
	(void)options;
	info.path = ":memory:";

	auto catalog = make_uniq<FusionCatalog>(db, std::move(state));
	catalog->Initialize(false);
	return std::move(catalog);
}

unique_ptr<TransactionManager> FusionCreateTransactionManager(optional_ptr<StorageExtensionInfo>, AttachedDatabase &db,
                                                              Catalog &) {
	// Legitimate only because the catalog is a DuckCatalog: the transaction
	// governs the local catalog, not anything on the Fusion side. Each scan
	// opens its own BI Publisher session and nothing spans them.
	return make_uniq<DuckTransactionManager>(db);
}

} // namespace

void RegisterFusionCatalog(ExtensionLoader &loader) {
	auto &config = DBConfig::GetConfig(loader.GetDatabaseInstance());
	config.AddExtensionOption("ofquack_filter_pushdown",
	                          "Send WHERE predicates on an attached Oracle Fusion table to Fusion. Off by default: "
	                          "DuckDB removes a pushed filter from the plan, so a predicate that cannot be "
	                          "translated exactly must fail the query rather than be approximated.",
	                          LogicalType::BOOLEAN, Value::BOOLEAN(false));

	auto extension = make_shared_ptr<StorageExtension>();
	extension->attach = FusionAttach;
	extension->create_transaction_manager = FusionCreateTransactionManager;
	StorageExtension::Register(config, STORAGE_TYPE, std::move(extension));
}

} // namespace duckdb
