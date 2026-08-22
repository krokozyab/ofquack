#include "ofquack/fusion_query_function.hpp"

#include "duckdb/function/table_function.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "ofquack/error_decoder.hpp"
#include "ofquack/errors.hpp"
#include "ofquack/fusion_connection.hpp"
#include "ofquack/transport.hpp"
#include "ofquack/xml_report.hpp"

#include <memory>
#include <string>
#include <vector>

namespace duckdb {

namespace {

struct FusionQueryBindData : public TableFunctionData {
	ofquack::FusionConfig config;
	FusionScanOptions options;
	string sql;
	//! Column names in SELECT order, taken from the first page.
	vector<string> columns;
	//! The first page, fetched during bind because the schema comes from it.
	ofquack::ParsedReport first_page;
};

struct FusionQueryGlobalState : public GlobalTableFunctionState {
	ofquack::ParsedReport page;
	idx_t offset_in_page = 0;

	idx_t MaxThreads() const override {
		// One BI Publisher session at a time: they are expensive and the server
		// accumulates them.
		return 1;
	}
};

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

unique_ptr<FunctionData> FusionQueryBind(ClientContext &context, TableFunctionBindInput &input,
                                         vector<LogicalType> &return_types, vector<string> &names) {
	auto bind_data = make_uniq<FusionQueryBindData>();
	bind_data->sql = input.inputs[0].GetValue<string>();
	if (bind_data->sql.empty()) {
		throw BinderException("oracle_fusion_query requires a SQL statement");
	}
	bind_data->config = ResolveFusionConfig(context, input.named_parameters, bind_data->options);

	// The schema lives in the data, so the first page is fetched here and kept
	// for the scan rather than being requested twice.
	auto transport = ofquack::CreateTransport(bind_data->config);
	const auto response = ExecuteOrThrow(*transport, bind_data->sql, context);
	bind_data->first_page = ParseResponseOrThrow(response, bind_data->sql);
	// duckdb::vector is its own type, not an alias for std::vector.
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
	for (const auto &column : bind_data->columns) {
		names.push_back(column);
		return_types.push_back(LogicalType::VARCHAR);
	}
	return std::move(bind_data);
}

unique_ptr<GlobalTableFunctionState> FusionQueryInitGlobal(ClientContext &context, TableFunctionInitInput &input) {
	auto &bind_data = input.bind_data->Cast<FusionQueryBindData>();
	auto state = make_uniq<FusionQueryGlobalState>();
	state->page = bind_data.first_page;
	return std::move(state);
}

void FusionQueryScan(ClientContext &context, TableFunctionInput &data, DataChunk &output) {
	auto &bind_data = data.bind_data->Cast<FusionQueryBindData>();
	auto &state = data.global_state->Cast<FusionQueryGlobalState>();
	const auto &rows = state.page.rows;

	if (state.offset_in_page >= rows.size()) {
		output.SetCardinality(0);
		return;
	}
	const idx_t to_emit = MinValue<idx_t>(STANDARD_VECTOR_SIZE, rows.size() - state.offset_in_page);
	output.SetCardinality(to_emit);

	for (idx_t column_index = 0; column_index < bind_data.columns.size(); column_index++) {
		auto &vector = output.data[column_index];
		auto entries = FlatVector::GetData<string_t>(vector);
		auto &validity = FlatVector::Validity(vector);
		const auto &column_name = bind_data.columns[column_index];

		for (idx_t row_index = 0; row_index < to_emit; row_index++) {
			const auto &row = rows[state.offset_in_page + row_index];
			const auto entry = row.find(column_name);
			if (entry == row.end()) {
				// dbms_xmlgen omits NULL elements, so an absent column is SQL
				// NULL. An element that is present but empty stays an empty
				// string -- the two are different values.
				validity.SetInvalid(row_index);
				continue;
			}
			entries[row_index] = StringVector::AddString(vector, entry->second);
		}
	}
	state.offset_in_page += to_emit;
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
