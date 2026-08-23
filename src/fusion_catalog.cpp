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

#include <cstdint>
#include <iterator>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <unordered_set>

namespace duckdb {

namespace {

constexpr const char *STORAGE_TYPE = "oracle_fusion";
constexpr int64_t CATALOG_CACHE_TTL_SECONDS = INT64_C(7) * 24 * 60 * 60;

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
	std::unordered_map<string, vector<string>> order_keys;

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
			int64_t expected = -1;
			tables = ofquack::FetchTables(*transport, RequestContextFor(context), {"TABLE", "VIEW"}, 0, &expected);
			cache.PutTables(endpoint_key, tables);
			cache.SetExpectedTables(endpoint_key, expected);
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

	//! The key a paged read seeks by: the primary key, or failing that a unique
	//! index over NOT NULL columns. From memory, then the file, then Fusion.
	//!
	//! Paging needs an order, and it needs one Oracle can walk through an index
	//! rather than sort the table for. Ordering by every column made the first
	//! page of XLA_AE_LINES a sort of several million rows by a hundred
	//! columns, which is how a `FETCH FIRST 100 ROWS` sat for two minutes. A
	//! unique index is accepted only over NOT NULL columns: a NULL in the key
	//! is a row nothing sorts after, and the seek would skip it.
	//!
	//! Empty means there is no key at all, which is answered with ROWID.
	const std::vector<string> &OrderKey(ClientContext &context, const ofquack::TableInfo &table) {
		const auto key = StringUtil::Upper(table.name);
		const auto known = order_keys.find(key);
		if (known != order_keys.end()) {
			return known->second;
		}
		std::vector<std::string> columns;
		auto &cache = MetadataCache::Get();
		if (!cache.TryGetOrderKey(endpoint_key, table.name, columns)) {
			const auto request_context = RequestContextFor(context);
			columns = ofquack::FetchPrimaryKey(*transport, request_context, table.name);
			if (columns.empty()) {
				std::unordered_set<string> nullable;
				for (const auto &column : Columns(context, table)) {
					if (column.nullable) {
						nullable.insert(StringUtil::Upper(column.name));
					}
				}
				for (const auto &index : ofquack::FetchUniqueIndexes(*transport, request_context, table.name)) {
					bool usable = true;
					for (const auto &column : index.columns) {
						usable = usable && nullable.count(StringUtil::Upper(column)) == 0;
					}
					if (usable) {
						columns = index.columns;
						break;
					}
				}
			}
			cache.PutOrderKey(endpoint_key, table.name, columns);
		}
		vector<string> as_duckdb;
		as_duckdb.assign(columns.begin(), columns.end());
		return order_keys.emplace(key, std::move(as_duckdb)).first->second;
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

	//! How pages are cut. KEYSET asks for the rows after the last one seen, in
	//! key order, so every page costs what a page should. OFFSET makes Oracle
	//! skip everything before the page, which grows with every page and makes
	//! a full read of a large table quadratic; it is what remains when there
	//! is no key to seek by. NONE is a single request.
	enum class PagingMode { NONE, OFFSET, KEYSET };
	PagingMode mode = PagingMode::NONE;

	//! One column of the seek key.
	struct KeyPart {
		string expression; //!< as written in the statement: "COL", or ROWID
		string xml_name;   //!< the element its value arrives in
		ofquack::KeyKind kind;
	};
	vector<KeyPart> key;
	//! The key of the last row received, as Oracle literals; empty before the
	//! first page.
	vector<string> last_key;
	//! SELECT ... FROM "T", with the key columns added when they were not
	//! projected -- the seek has to read them back.
	string select_from;
	string order_clause;

	//! The statement for OFFSET and NONE, order included.
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

//! How a key column's value is written back into a seek, by its DuckDB type.
//! False for a type whose text cannot be turned into an Oracle literal safely.
bool KeyKindOf(const LogicalType &type, ofquack::KeyKind &kind) {
	switch (type.id()) {
	case LogicalTypeId::INTEGER:
	case LogicalTypeId::BIGINT:
	case LogicalTypeId::DECIMAL:
		kind = ofquack::KeyKind::NUMBER;
		return true;
	case LogicalTypeId::VARCHAR:
		kind = ofquack::KeyKind::TEXT;
		return true;
	case LogicalTypeId::DATE:
		kind = ofquack::KeyKind::DATE;
		return true;
	case LogicalTypeId::TIMESTAMP:
		kind = ofquack::KeyKind::TIMESTAMP;
		return true;
	default:
		return false;
	}
}

[[noreturn]] void RethrowAsDatabaseError(const ofquack::FusionError &error, const string &sql) {
	throw IOException("%s\nSQL: %s", error.what(), sql);
}

//! The statement for the next page, by the scan's paging mode.
string NextPageStatement(const FusionCatalogScanBindData &bind_data, const FusionCatalogScanState &state,
                         idx_t offset) {
	const auto fetch_size = bind_data.state->options.fetch_size;
	switch (state.mode) {
	case FusionCatalogScanState::PagingMode::NONE:
		return state.base_sql;
	case FusionCatalogScanState::PagingMode::OFFSET:
		return ofquack::ApplyPagination(state.base_sql, offset, fetch_size);
	case FusionCatalogScanState::PagingMode::KEYSET: {
		auto statement = state.select_from;
		vector<string> conditions;
		if (!state.where_clause.empty()) {
			conditions.push_back("(" + state.where_clause + ")");
		}
		if (!state.last_key.empty()) {
			std::vector<std::string> expressions;
			for (const auto &part : state.key) {
				expressions.push_back(part.expression);
			}
			conditions.push_back(ofquack::SeekPredicate(expressions, std::vector<std::string>(state.last_key.begin(),
			                                                                                   state.last_key.end())));
		}
		if (!conditions.empty()) {
			statement += " WHERE " + StringUtil::Join(conditions, " AND ");
		}
		return statement + " ORDER BY " + state.order_clause + " FETCH FIRST " + std::to_string(fetch_size) +
		       " ROWS ONLY";
	}
	}
	return state.base_sql;
}

//! Records the key of the last row of a page, which is where the next page
//! starts. A key that cannot be read back -- NULL, or a value that will not
//! make a literal -- leaves nowhere to continue from, and says so.
void NoteLastKey(FusionCatalogScanState &state, const string &object_name) {
	if (state.mode != FusionCatalogScanState::PagingMode::KEYSET || state.page.rows.empty()) {
		return;
	}
	const auto &last = state.page.rows.back();
	vector<string> literals;
	for (const auto &part : state.key) {
		const auto found = last.find(part.xml_name);
		const auto literal = found == last.end() ? std::string() : ofquack::KeyLiteral(part.kind, found->second);
		if (literal.empty()) {
			throw IOException("Cannot continue reading %s: key column %s is NULL or unreadable in the last row of a "
			                  "page, so there is nowhere to seek to. Read the table with stable_paging := false, or "
			                  "through oracle_fusion_query with an ORDER BY of your own",
			                  object_name, part.expression);
		}
		literals.push_back(literal);
	}
	if (literals == state.last_key) {
		throw IOException("Oracle Fusion returned the same last row again for %s, so the seek is not advancing and "
		                  "reading it would never end",
		                  object_name);
	}
	state.last_key = std::move(literals);
}

ofquack::ParsedReport FetchCatalogPage(FusionCatalogScanBindData &bind_data, FusionCatalogScanState &state,
                                       ClientContext &context, idx_t offset) {
	const auto statement = NextPageStatement(bind_data, state, offset);
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
		// "Missing SOAP Envelope" on its own says what the response was not,
		// which is no help; the first line of what did arrive usually is.
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

	const auto from_table = " FROM " + KeywordHelper::WriteQuoted(bind_data.object_name, '"');
	const auto where = state->where_clause.empty() ? string() : " WHERE " + state->where_clause;
	state->paginate = ofquack::ClassifyForPagination("SELECT " + select_list + from_table + where,
	                                                 bind_data.state->options.fetch_size) ==
	                  ofquack::PaginationVerdict::YES;
	state->mode = state->paginate ? FusionCatalogScanState::PagingMode::OFFSET
	                              : FusionCatalogScanState::PagingMode::NONE;

	// Paging needs an order: each page is a separate execution of the
	// statement, and Oracle owes no two executions the same row order, so
	// without one a page can repeat rows the previous one returned and skip
	// others -- invisibly, since every page is individually well formed.
	//
	// And the order decides what a page costs. With a key to seek by, a page
	// asks for the rows after the last one it saw and Oracle walks the index
	// to them: every page costs the same. Anything else makes Oracle skip or
	// sort everything before the page, which grows with every page until a
	// large table never finishes -- a full read of AP_INVOICES_ALL sat for
	// four minutes without producing a row.
	string order_by_names;
	bool is_view = true;
	if (state->paginate && bind_data.state->options.stable_paging) {
		auto table = bind_data.state->FindTable(context, bind_data.object_name);
		is_view = !table || StringUtil::CIEquals(table->type, "VIEW");
		if (!is_view) {
			vector<FusionCatalogScanState::KeyPart> parts;
			bool seekable = true;
			for (const auto &name : bind_data.state->OrderKey(context, *table)) {
				order_by_names += (order_by_names.empty() ? "" : ", ") + KeywordHelper::WriteQuoted(name, '"');
				optional_ptr<const FusionColumn> column;
				for (const auto &candidate : bind_data.columns) {
					if (StringUtil::CIEquals(candidate.name, name)) {
						column = &candidate;
					}
				}
				ofquack::KeyKind kind = ofquack::KeyKind::TEXT;
				if (!column || !column->type_from_dictionary || !KeyKindOf(column->type, kind)) {
					// A key of a type whose value cannot be written back as a
					// literal: the order still holds, the seek does not.
					seekable = false;
					continue;
				}
				parts.push_back({KeywordHelper::WriteQuoted(name, '"'), column->name, kind});
			}
			if (seekable && parts.empty()) {
				// No key at all. ROWID is unique and, short of row movement,
				// stable; a seek on it is a range scan from where the last page
				// ended rather than a sort of the table.
				parts.push_back({"ROWID", "OFQUACK_ROWID", ofquack::KeyKind::ROWID});
			}
			if (seekable) {
				state->mode = FusionCatalogScanState::PagingMode::KEYSET;
				state->key = std::move(parts);
				for (const auto &part : state->key) {
					// The seek reads the key back from each page, so the key
					// travels with it even when it was not asked for.
					bool projected = false;
					for (const auto &name : state->projected_names) {
						projected = projected || StringUtil::CIEquals(name, part.xml_name);
					}
					if (!projected) {
						select_list += ", " + (part.kind == ofquack::KeyKind::ROWID
						                           ? string("ROWID AS \"OFQUACK_ROWID\"")
						                           : part.expression);
					}
					state->order_clause += (state->order_clause.empty() ? "" : ", ") + part.expression;
				}
			}
		}
	}

	state->select_from = "SELECT " + select_list + from_table;
	state->base_sql = state->select_from + where;
	if (state->mode == FusionCatalogScanState::PagingMode::OFFSET && bind_data.state->options.stable_paging) {
		if (!order_by_names.empty()) {
			// A key that orders but cannot be sought: by name, since Oracle
			// allows ordering by a column it does not return.
			state->base_sql += " ORDER BY " + order_by_names;
		} else if (!is_view) {
			state->base_sql += " ORDER BY ROWID";
		} else {
			// A view has no key. Every projected column is a total order on
			// the output -- rows that tie on all of them are interchangeable --
			// and it is the only order there is, whatever it costs.
			std::vector<uint64_t> positions;
			for (idx_t i = 0; i < selected.size(); i++) {
				if (ofquack::IsSortableOracleType(bind_data.columns[selected[i]].oracle_type_name)) {
					positions.push_back(static_cast<uint64_t>(i) + 1);
				}
			}
			state->base_sql = ofquack::AppendOrderByPositions(state->base_sql, positions);
		}
	}

	state->page = FetchCatalogPage(bind_data, *state, context, 0);
	NoteLastKey(*state, bind_data.object_name);
	if (state->page.truncated && !state->paginate) {
		// Paging carries on from the rows received; without it the rows past
		// the cut are gone, and a silent short answer is worse than an error.
		throw IOException("Oracle Fusion cut the response off after %llu rows (%llu bytes) of %s: the report "
		                  "returns at most that much in one response, and paging is off (fetch_size := 0). Turn "
		                  "paging on so the table is read in pages",
		                  static_cast<uint64_t>(state->page.rows.size()),
		                  static_cast<uint64_t>(state->page.truncated_at_bytes), bind_data.object_name);
	}
	state->more_pages = state->paginate && !state->page.rows.empty();
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
		auto fetched = FetchCatalogPage(bind_data, state, context, state.rows_emitted);
		// A report that ignores the row-limiting clause would hand back the same
		// rows for ever now that only an empty page ends a scan.
		if (!state.page.rows.empty() && !fetched.rows.empty() && state.page.rows.front() == fetched.rows.front()) {
			throw IOException("Oracle Fusion returned the same rows again for OFFSET %llu of %s, so the statement is "
			                  "not being paged and reading it would never end",
			                  static_cast<uint64_t>(state.rows_emitted), bind_data.object_name);
		}
		state.page = std::move(fetched);
		state.offset_in_page = 0;
		NoteLastKey(state, bind_data.object_name);
		// Only an empty page ends the scan. A short one used to, and that is
		// wrong twice over: BI Publisher truncates a response that grows too
		// large without saying so, and a truncated page is indistinguishable
		// from the last one. The price of being sure is one request per scan.
		state.more_pages = !state.page.rows.empty();
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
			// Not ours. DuckDB asks every attached catalog about every name,
			// including its own system tables, so this is the normal answer.
			return nullptr;
		}
		const auto &columns = state->Columns(context, *table);
		if (columns.empty()) {
			// The name *is* in Fusion's dictionary, so reporting that it does
			// not exist would be a lie that sends the user looking for a typo.
			// FND_TABLES lists objects with no rows in FND_COLUMNS at all.
			throw BinderException(
			    "Oracle Fusion lists \"%s\" but returned no column information for it, so it cannot be "
			    "queried through the catalog.\nSELECT * FROM oracle_fusion_columns('%s') shows what the "
			    "dictionary says. Querying it directly still works:\n"
			    "  SELECT * FROM oracle_fusion_query('SELECT * FROM %s WHERE ROWNUM <= 100');",
			    table->name, table->name, table->name);
		}

		auto info = make_uniq<CreateTableInfo>();
		info->schema = schema.name;
		info->table = table->name;
		vector<FusionColumn> fusion_columns;
		for (const auto &column : columns) {
			bool from_dictionary = false;
			auto type = TypeOf(column, from_dictionary);
			info->columns.AddColumn(ColumnDefinition(column.name, type));
			fusion_columns.push_back(FusionColumn {column.name, type, column.type_name, from_dictionary});
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
		function.name = "fusion_scanner_attached_scan";
		function.get_bind_info = FusionCatalogScanBindInfo;
		function.projection_pushdown = true;

		Value pushdown;
		function.filter_pushdown =
		    context.TryGetCurrentSetting("fusion_scanner_filter_pushdown", pushdown) && BooleanValue::Get(pushdown);
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

	//! Every name returned here MUST be creatable by CreateDefaultEntry.
	//!
	//! DuckDB treats a name it was offered and then refused as an internal
	//! error and aborts the whole scan -- so listing a table whose columns turn
	//! out to be unavailable takes down `SHOW TABLES` and every catalog browser
	//! with it. Fusion's dictionary has plenty of those: FND_TABLES lists
	//! objects that have no rows in FND_COLUMNS.
	//!
	//! So only tables whose columns are already known are offered. Cold, that
	//! is none: the alternative is a multi-second dictionary read per table
	//! before the list can even be returned, from a callback that has no
	//! ClientContext to cancel. Use fusion_scanner_cache_warm() to fill it in.
	vector<string> GetDefaultEntries() override {
		std::lock_guard<std::mutex> guard(state->metadata_lock);
		if (!state->tables_loaded) {
			std::vector<ofquack::TableInfo> cached;
			if (MetadataCache::Get().TryGetTables(state->endpoint_key, CATALOG_CACHE_TTL_SECONDS, cached)) {
				state->tables = std::move(cached);
				state->tables_loaded = true;
			}
		}

		vector<string> names;
		auto &cache = MetadataCache::Get();
		for (const auto &table : state->tables) {
			const auto key = StringUtil::Upper(table.name);
			const auto known = state->columns_by_table.find(key);
			if (known != state->columns_by_table.end()) {
				if (!known->second.empty()) {
					names.push_back(table.name);
				}
				continue;
			}
			// Reading the cache is cheap and local; asking Fusion is not, and
			// is not done here.
			std::vector<ofquack::ColumnInfo> columns;
			if (cache.TryGetColumns(state->endpoint_key, table.name, CATALOG_CACHE_TTL_SECONDS, columns) &&
			    !columns.empty()) {
				state->columns_by_table.emplace(key, std::move(columns));
				names.push_back(table.name);
			}
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
		auto table_generator = make_uniq<FusionTableGenerator>(*this, schema, state);
		generator = table_generator.get();
		schema.GetCatalogSet(CatalogType::TABLE_ENTRY).SetDefaultGenerator(std::move(table_generator));
	}

	//! Every entry lookup passes through here first, which makes it the place
	//! to undo what a schema listing does to the generator.
	//!
	//! Once CatalogSet::Scan has asked the generator for all its entries -- a
	//! SHOW TABLES, a client expanding the table tree, even the "did you mean"
	//! search after a failed lookup -- it sets created_all_entries, and from
	//! then on a name that is not already an entry is never offered to the
	//! generator again. For a generator whose listing is deliberately partial
	//! (only tables whose columns are cached; the rest would cost a request
	//! each) that froze the catalog: a table first asked for after the
	//! listing "did not exist", however real it was. Clearing the flag before
	//! each lookup keeps the generator in the loop. The listing is repeated on
	//! the next scan as a consequence, which costs one read of the cache.
	optional_ptr<SchemaCatalogEntry> LookupSchema(CatalogTransaction transaction, const EntryLookupInfo &schema_lookup,
	                                              OnEntryNotFound if_not_found) override {
		if (generator) {
			generator->created_all_entries = false;
		}
		return DuckCatalog::LookupSchema(transaction, schema_lookup, if_not_found);
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
	//! Owned by the table CatalogSet; kept here to reset its flag on lookup.
	optional_ptr<FusionTableGenerator> generator;
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
	// Consumed here, and removed so that nothing downstream sees them. A
	// DuckCatalog opens a local StorageManager, and that one rejects any
	// option it does not know -- "Unrecognized option for attach
	// \"fetch_size\"" -- without knowing that the option was ours.
	options.options.clear();
	for (auto entry = info.options.begin(); entry != info.options.end();) {
		entry = StringUtil::Lower(entry->first) == "type" ? std::next(entry) : info.options.erase(entry);
	}

	state->config = ResolveFusionConfig(context, parameters, state->options);
	RequireUsableCredentials(state->config);
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
	config.AddExtensionOption("fusion_scanner_filter_pushdown",
	                          "Send WHERE predicates on an attached Oracle Fusion table to Fusion. Off by default: "
	                          "DuckDB removes a pushed filter from the plan, so a predicate that cannot be "
	                          "translated exactly must fail the query rather than be approximated.",
	                          LogicalType::BOOLEAN, Value::BOOLEAN(false));
	config.AddExtensionOption("fusion_scanner_stable_paging",
	                          "Give a paged statement an order, so that its pages partition the result instead of "
	                          "sampling it: an attached table by its primary key (or ROWID), a query by every "
	                          "column it returns. On by default; turn it off only if Oracle refuses the ordering, "
	                          "and expect pages to repeat and skip rows when you do.",
	                          LogicalType::BOOLEAN, Value::BOOLEAN(true));

	auto extension = make_shared_ptr<StorageExtension>();
	extension->attach = FusionAttach;
	extension->create_transaction_manager = FusionCreateTransactionManager;
	StorageExtension::Register(config, STORAGE_TYPE, std::move(extension));
}

} // namespace duckdb
