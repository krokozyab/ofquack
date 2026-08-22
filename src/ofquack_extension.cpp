#define DUCKDB_EXTENSION_MAIN

#include "ofquack_extension.hpp"

#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/helper.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "ofquack/transport.hpp"
#include "ofquack/xml_report.hpp"

#include <curl/curl.h>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace duckdb {

namespace {

struct FusionBindData : public TableFunctionData {
	ofquack::FusionConfig config;
	string sql;
	vector<string> columns;
	vector<ofquack::ReportRow> rows;
};

struct FusionLocalState : public LocalTableFunctionState {
	idx_t offset = 0;
};

//! Derives column names from the SQL text when the report came back empty.
//!
//! This only exists because an empty result carries no schema at all, and a
//! table function must still describe one. It is a guess: the split is naive
//! and breaks on commas inside function calls or subqueries.
void DeriveColumnsFromSQL(const string &sql, vector<string> &columns) {
	string cols_txt;
	const auto select_pos = sql.find("SELECT");
	const auto from_pos = sql.find("FROM");
	if (select_pos != string::npos && from_pos != string::npos && from_pos > select_pos) {
		cols_txt = sql.substr(select_pos + 6, from_pos - (select_pos + 6));
	}

	vector<string> parts;
	std::istringstream stream(cols_txt);
	string part;
	while (std::getline(stream, part, ',')) {
		const auto first = part.find_first_not_of(" \t\n\r");
		if (first == string::npos) {
			continue;
		}
		const auto last = part.find_last_not_of(" \t\n\r");
		parts.push_back(part.substr(first, last - first + 1));
	}

	if (parts.empty() || (parts.size() == 1 && parts[0] == "*")) {
		columns.push_back("RESULT");
		return;
	}
	for (auto &name : parts) {
		columns.push_back(std::move(name));
	}
}

unique_ptr<FunctionData> FusionBind(ClientContext &context, TableFunctionBindInput &input,
                                    vector<LogicalType> &return_types, vector<string> &names) {
	auto bind_data = make_uniq<FusionBindData>();
	bind_data->config.endpoint = input.inputs[0].GetValue<string>();
	bind_data->config.username = input.inputs[1].GetValue<string>();
	bind_data->config.password = input.inputs[2].GetValue<string>();
	bind_data->config.report_path = input.inputs[3].GetValue<string>();
	bind_data->sql = input.inputs[4].GetValue<string>();

	auto transport = ofquack::CreateTransport(bind_data->config);
	const auto soap_xml = transport->Execute(bind_data->sql, ofquack::RequestContext::None());

	std::set<string> cols;
	try {
		bind_data->rows = ofquack::ParseRows(ofquack::ExtractReportXML(soap_xml), cols);
	} catch (const std::runtime_error &) {
		// A SOAP fault or a report with no data leaves rows and cols empty.
		// Swallowing it here is wrong -- the caller cannot tell "no rows" from
		// "the server refused" -- but turning it into an error is a contract
		// change, so it is left for the rewrite of this function.
	}

	// Columns arrive from a std::set, so they are alphabetical rather than in
	// SELECT order. Preserved here deliberately: fixing it belongs with the
	// new query function, not with this move.
	for (const auto &col : cols) {
		bind_data->columns.push_back(col);
	}
	if (bind_data->columns.empty()) {
		DeriveColumnsFromSQL(bind_data->sql, bind_data->columns);
	}
	for (const auto &col : bind_data->columns) {
		names.push_back(col);
		return_types.push_back(LogicalType::VARCHAR);
	}
	return std::move(bind_data);
}

unique_ptr<LocalTableFunctionState> FusionInitLocal(ExecutionContext &context, TableFunctionInitInput &input,
                                                    GlobalTableFunctionState *global_state) {
	return make_uniq<FusionLocalState>();
}

void FusionScan(ClientContext &context, TableFunctionInput &data, DataChunk &output) {
	auto &bind_data = data.bind_data->Cast<FusionBindData>();
	auto &local_state = data.local_state->Cast<FusionLocalState>();
	auto &rows = bind_data.rows;

	const idx_t total = rows.size();
	if (local_state.offset >= total) {
		output.SetCardinality(0);
		return;
	}
	const idx_t to_emit = MinValue<idx_t>(STANDARD_VECTOR_SIZE, total - local_state.offset);
	output.SetCardinality(to_emit);
	for (idx_t row_idx = 0; row_idx < to_emit; row_idx++) {
		auto &row = rows[local_state.offset + row_idx];
		for (idx_t col_idx = 0; col_idx < bind_data.columns.size(); col_idx++) {
			auto &vec = output.data[col_idx];
			const auto entry = row.find(bind_data.columns[col_idx]);
			const auto &value = entry != row.end() ? entry->second : string();
			FlatVector::GetData<string_t>(vec)[row_idx] = StringVector::AddString(vec, value);
		}
	}
	local_state.offset += to_emit;
}

//! libcurl requires one global initialisation before any easy handle exists.
//! There is deliberately no paired curl_global_cleanup: the new extension ABI
//! has no shutdown hook to call it from, and calling it from a static
//! destructor would race libcurl's background threads.
void EnsureCurlInitialized() {
	static std::once_flag curl_init_flag;
	std::call_once(curl_init_flag, []() { curl_global_init(CURL_GLOBAL_DEFAULT); });
}

} // namespace

static void LoadInternal(ExtensionLoader &loader) {
	EnsureCurlInitialized();
	loader.SetDescription("Query Oracle Fusion via BI Publisher SOAP calls");

	TableFunctionSet fusion_query("oracle_fusion_wsdl_query");
	fusion_query.AddFunction(TableFunction({LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR,
	                                        LogicalType::VARCHAR, LogicalType::VARCHAR},
	                                       FusionScan, FusionBind,
	                                       nullptr, // no global state: the scan is single threaded
	                                       FusionInitLocal));
	loader.RegisterFunction(fusion_query);
}

void OfquackExtension::Load(ExtensionLoader &loader) {
	LoadInternal(loader);
}

std::string OfquackExtension::Name() {
	return "ofquack";
}

std::string OfquackExtension::Version() const {
#ifdef EXT_VERSION_OFQUACK
	return EXT_VERSION_OFQUACK;
#else
	return "";
#endif
}

} // namespace duckdb

extern "C" {

DUCKDB_CPP_EXTENSION_ENTRY(ofquack, loader) {
	duckdb::LoadInternal(loader);
}

} // extern "C"
