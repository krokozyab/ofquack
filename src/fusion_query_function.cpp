#include "ofquack/fusion_query_function.hpp"

#include "duckdb/function/table_function.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "ofquack/error_decoder.hpp"
#include "ofquack/errors.hpp"
#include "ofquack/fusion_connection.hpp"
#include "ofquack/secured_views.hpp"
#include "ofquack/sql_rewrite.hpp"
#include "ofquack/sql_text.hpp"
#include "ofquack/transport.hpp"
#include "ofquack/type_inference.hpp"
#include "ofquack/xml_report.hpp"

#include <memory>
#include <string>
#include <vector>

namespace duckdb {

namespace {

struct FusionQueryBindData : public TableFunctionData {
	ofquack::FusionConfig config;
	FusionScanOptions options;
	//! The statement as normalised, which is what actually goes to Fusion.
	string sql;
	vector<string> columns;
	vector<LogicalType> column_types;
	//! The first page, fetched during bind because the schema comes from it.
	ofquack::ParsedReport first_page;
	//! False when the statement carries its own OFFSET/FETCH or uses ROWNUM, in
	//! which case the first page is the whole result.
	bool paginate = false;
	//! Created once and shared with the scan, so every page of one result runs
	//! over the same connection and keeps the BI Publisher session cookie.
	//! std:: is explicit: inside namespace duckdb an unqualified shared_ptr is
	//! duckdb's own, which does not accept a std::shared_ptr.
	std::shared_ptr<ofquack::FusionTransport> transport;
};

struct FusionQueryGlobalState : public GlobalTableFunctionState {
	ofquack::ParsedReport page;
	idx_t offset_in_page = 0;
	//! Rows already handed to DuckDB, which is also the OFFSET of the next page.
	idx_t rows_emitted = 0;
	bool more_pages = false;

	idx_t MaxThreads() const override {
		// One BI Publisher session at a time: they are expensive and the server
		// accumulates them.
		return 1;
	}
};

std::string ExecuteOrThrow(ofquack::FusionTransport &transport, const std::string &sql, ClientContext &context);
ofquack::ParsedReport ParseResponseOrThrow(const std::string &soap_xml, const std::string &sql);

//! Runs one statement, translating the transport's exceptions into DuckDB's.
//!
//! Without this every failure surfaced as a bare "Invalid Error", which tells
//! the user nothing about whether to fix their query, their credentials or
//! their network. Cancellation is wired to the same flag Ctrl-C sets, so a
//! query stuck on a slow report can be interrupted.
std::string ExecuteOrThrow(ofquack::FusionTransport &transport, const std::string &sql, ClientContext &context) {
	ofquack::RequestContext request_context;
	request_context.is_cancelled = [&context]() { return context.interrupted.load(); };

	try {
		return transport.Execute(sql, request_context);
	} catch (const ofquack::CancelledError &) {
		throw InterruptException();
	} catch (const ofquack::AuthenticationError &auth_error) {
		throw InvalidInputException("%s", auth_error.what());
	} catch (const ofquack::CircuitOpenError &circuit_error) {
		throw IOException("%s", circuit_error.what());
	} catch (const ofquack::FusionError &fusion_error) {
		throw IOException("%s\nSQL: %s", fusion_error.what(), sql);
	}
}

//! Turns a SOAP response into rows, reporting a fault as an error rather than
//! as an empty result. Silently returning no rows is how a permissions problem
//! or a bad table name used to look exactly like a query that matched nothing.
ofquack::ParsedReport ParseResponseOrThrow(const std::string &soap_xml, const std::string &sql) {
	try {
		return ofquack::ParseRows(ofquack::ExtractReportXML(soap_xml));
	} catch (const std::runtime_error &parse_error) {
		const auto reported = ofquack::DescribeFailure(soap_xml);
		if (!reported.empty()) {
			throw IOException("Oracle Fusion rejected the query: %s\nSQL: %s", reported, sql);
		}
		throw IOException("Could not read the Oracle Fusion report response: %s\nSQL: %s", parse_error.what(), sql);
	}
}

//! Fetches one page. `offset` is ignored when the statement cannot be paged.
ofquack::ParsedReport FetchPage(ofquack::FusionTransport &transport, const FusionQueryBindData &bind_data,
                                ClientContext &context, idx_t offset) {
	const auto statement = bind_data.paginate
	                           ? ofquack::ApplyPagination(bind_data.sql, offset, bind_data.options.fetch_size)
	                           : bind_data.sql;
	return ParseResponseOrThrow(ExecuteOrThrow(transport, statement, context), statement);
}

LogicalType ToLogicalType(const ofquack::InferredColumn &inferred) {
	switch (inferred.type) {
	case ofquack::InferredType::INTEGER:
		return LogicalType::INTEGER;
	case ofquack::InferredType::BIGINT:
		return LogicalType::BIGINT;
	case ofquack::InferredType::DECIMAL:
		// Widest precision Oracle NUMBER can hold; the scale comes from the data.
		return LogicalType::DECIMAL(38, inferred.scale);
	case ofquack::InferredType::DATE:
		return LogicalType::DATE;
	case ofquack::InferredType::TIMESTAMP:
		return LogicalType::TIMESTAMP;
	case ofquack::InferredType::VARCHAR:
	default:
		return LogicalType::VARCHAR;
	}
}

//! Infers a type per column from the first page.
void InferColumnTypes(const ofquack::ParsedReport &page, const vector<string> &columns,
                      vector<LogicalType> &column_types) {
	for (const auto &column : columns) {
		std::vector<std::string> samples;
		samples.reserve(ofquack::TYPE_SAMPLE_ROWS);
		for (const auto &row : page.rows) {
			if (samples.size() >= ofquack::TYPE_SAMPLE_ROWS) {
				break;
			}
			const auto entry = row.find(column);
			if (entry != row.end()) {
				samples.push_back(entry->second);
			}
		}
		column_types.push_back(ToLogicalType(ofquack::InferColumnType(samples)));
	}
}

unique_ptr<FunctionData> FusionQueryBind(ClientContext &context, TableFunctionBindInput &input,
                                         vector<LogicalType> &return_types, vector<string> &names) {
	auto bind_data = make_uniq<FusionQueryBindData>();
	const auto raw_sql = input.inputs[0].GetValue<string>();
	if (raw_sql.empty()) {
		throw BinderException("oracle_fusion_query requires a SQL statement");
	}
	// Normalised once here, so the paging rewrite and the statement that
	// reaches Fusion are the same text.
	bind_data->sql = ofquack::NormalizeSql(raw_sql);
	if (bind_data->sql.empty()) {
		throw BinderException("oracle_fusion_query requires a SQL statement");
	}
	bind_data->config = ResolveFusionConfig(context, input.named_parameters, bind_data->options);
	RequireUsableCredentials(bind_data->config);
	if (bind_data->options.secured_views) {
		// Applied before paging, so the rewritten name is what gets limited.
		bind_data->sql = ofquack::ApplySecuredViews(bind_data->sql);
	}
	bind_data->paginate =
	    ofquack::ClassifyForPagination(bind_data->sql, bind_data->options.fetch_size) == ofquack::PaginationVerdict::YES;

	// The schema lives in the data, so the first page is fetched here and kept
	// for the scan rather than being requested twice.
	bind_data->transport = ofquack::CreateTransport(bind_data->config);
	bind_data->first_page = FetchPage(*bind_data->transport, *bind_data, context, 0);
	bind_data->columns.assign(bind_data->first_page.columns.begin(), bind_data->first_page.columns.end());

	if (bind_data->columns.empty()) {
		// An empty report carries no schema at all. Guessing column names by
		// slicing the SQL text -- which is what this used to do -- produced
		// nonsense on any query with a function call or a subquery in its
		// select list, and the guess silently became the table's schema.
		throw IOException(
		    "Oracle Fusion returned no rows, so the result has no columns and its schema is unknown.\n"
		    "Add a predicate that matches at least one row, or wrap the query so it always returns one "
		    "(for example SELECT … FROM DUAL).\nSQL: %s",
		    bind_data->sql);
	}

	if (bind_data->options.all_varchar) {
		bind_data->column_types.assign(bind_data->columns.size(), LogicalType::VARCHAR);
	} else {
		InferColumnTypes(bind_data->first_page, bind_data->columns, bind_data->column_types);
	}
	for (idx_t i = 0; i < bind_data->columns.size(); i++) {
		names.push_back(bind_data->columns[i]);
		return_types.push_back(bind_data->column_types[i]);
	}
	return std::move(bind_data);
}

unique_ptr<GlobalTableFunctionState> FusionQueryInitGlobal(ClientContext &context, TableFunctionInitInput &input) {
	auto &bind_data = input.bind_data->Cast<FusionQueryBindData>();
	auto state = make_uniq<FusionQueryGlobalState>();
	state->page = bind_data.first_page;
	// A short page means the source is exhausted, so the common case of a
	// result smaller than one page costs exactly one request.
	state->more_pages = bind_data.paginate && state->page.rows.size() == bind_data.options.fetch_size;
	return std::move(state);
}

//! Writes one column of the current page into the output vector.
void EmitColumn(Vector &vector, const std::vector<ofquack::ReportRow> &rows, idx_t from, idx_t count,
                const string &column_name, const LogicalType &type) {
	auto &validity = FlatVector::Validity(vector);
	const bool as_varchar = type.id() == LogicalTypeId::VARCHAR;
	auto entries = as_varchar ? FlatVector::GetData<string_t>(vector) : nullptr;

	for (idx_t row_index = 0; row_index < count; row_index++) {
		const auto &row = rows[from + row_index];
		const auto entry = row.find(column_name);
		if (entry == row.end()) {
			// dbms_xmlgen omits NULL elements, so an absent column is SQL NULL.
			// An element that is present but empty stays an empty string --
			// the two are different values.
			validity.SetInvalid(row_index);
			continue;
		}
		if (as_varchar) {
			entries[row_index] = StringVector::AddString(vector, entry->second);
			continue;
		}
		if (entry->second.empty()) {
			validity.SetInvalid(row_index);
			continue;
		}
		// The type was inferred from a sample, so a later row can disagree.
		// Such a value becomes NULL rather than failing the query: one odd row
		// in a million should not cost the user the other 999,999. Use
		// all_varchar := true to see the raw text instead.
		//
		// The error string is not optional: passing nullptr makes TryCast
		// throw rather than report, which is the opposite of what is wanted.
		Value converted;
		string conversion_error;
		if (!Value(entry->second).DefaultTryCastAs(type, converted, &conversion_error)) {
			validity.SetInvalid(row_index);
			continue;
		}
		vector.SetValue(row_index, converted);
	}
}

void FusionQueryScan(ClientContext &context, TableFunctionInput &data, DataChunk &output) {
	auto &bind_data = data.bind_data->Cast<FusionQueryBindData>();
	auto &state = data.global_state->Cast<FusionQueryGlobalState>();

	// Pages are fetched lazily: the next request is only made once the current
	// page has been fully handed over.
	while (state.offset_in_page >= state.page.rows.size()) {
		if (!state.more_pages) {
			output.SetCardinality(0);
			return;
		}
		state.page = FetchPage(*bind_data.transport, bind_data, context, state.rows_emitted);
		state.offset_in_page = 0;
		state.more_pages = state.page.rows.size() == bind_data.options.fetch_size;
	}

	const idx_t to_emit =
	    MinValue<idx_t>(STANDARD_VECTOR_SIZE, state.page.rows.size() - state.offset_in_page);
	output.SetCardinality(to_emit);
	for (idx_t column_index = 0; column_index < bind_data.columns.size(); column_index++) {
		EmitColumn(output.data[column_index], state.page.rows, state.offset_in_page, to_emit,
		           bind_data.columns[column_index], bind_data.column_types[column_index]);
	}
	state.offset_in_page += to_emit;
	state.rows_emitted += to_emit;
}

//! The removed positional function, kept for one release so the old call site
//! gets an explanation instead of "function does not exist".
unique_ptr<FunctionData> RemovedWsdlQueryBind(ClientContext &, TableFunctionBindInput &, vector<LogicalType> &,
                                              vector<string> &) {
	throw BinderException(
	    "oracle_fusion_wsdl_query() has been replaced by oracle_fusion_query(), which takes the "
	    "connection from a secret so credentials never appear in SQL text or query history:\n\n"
	    "  CREATE SECRET fusion (\n"
	    "      TYPE oracle_fusion,\n"
	    "      ENDPOINT 'https://<host>/xmlpserver/services/ExternalReportWSSService?WSDL',\n"
	    "      REPORT_PATH '/Custom/Financials/RP_ARB.xdo',\n"
	    "      USERNAME '<user>', PASSWORD '<password>');\n\n"
	    "  SELECT * FROM oracle_fusion_query('SELECT … FROM …');");
}

void RemovedWsdlQueryScan(ClientContext &, TableFunctionInput &, DataChunk &) {
	throw InternalException("oracle_fusion_wsdl_query should have failed to bind");
}

} // namespace

void RegisterFusionQueryFunction(ExtensionLoader &loader) {
	TableFunction query("oracle_fusion_query", {LogicalType::VARCHAR}, FusionQueryScan, FusionQueryBind,
	                    FusionQueryInitGlobal);
	AddFusionNamedParameters(query);
	loader.RegisterFunction(query);

	TableFunction removed("oracle_fusion_wsdl_query",
	                      {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR,
	                       LogicalType::VARCHAR},
	                      RemovedWsdlQueryScan, RemovedWsdlQueryBind);
	loader.RegisterFunction(removed);
}

} // namespace duckdb
