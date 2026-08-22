// Drives the table function end to end against a scripted transport: no Fusion
// instance, no network, no credentials.
//
// This is the test the repository did not have. The only SQL test that existed
// was `SELECT 1`, because everything interesting sat behind a live SOAP call.

// Before any include. Windows defines min and max as function-like macros, and
// the headers pulled in below reach <windows.h>, which rewrites `(std::min)(...)`.
#if defined(_WIN32) && !defined(NOMINMAX)
#define NOMINMAX
#endif

#include "ofquack/transport.hpp"
#include "ofquack_extension.hpp"

#include "base64.h"
#include "duckdb.hpp"

#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

[[noreturn]] static void CheckFailed(const char *expression, const char *file, int line) {
	std::cerr << file << ":" << line << ": check failed: " << expression << std::endl;
	std::abort();
}

#define CHECK(expression)                                                                                              \
	do {                                                                                                               \
		if (!(expression)) {                                                                                           \
			CheckFailed(#expression, __FILE__, __LINE__);                                                              \
		}                                                                                                              \
	} while (0)

using duckdb::Connection;
using duckdb::DuckDB;

using ofquack::FusionConfig;
using ofquack::FusionTransport;
using ofquack::RequestContext;
using ofquack::ScopedTransportFactory;

namespace {

std::string MakeSoapResponse(const std::string &report_xml) {
	const auto encoded = base64_encode(reinterpret_cast<const unsigned char *>(report_xml.c_str()), report_xml.size());
	return "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\"><soap:Body>"
	       "<ns2:runReportResponse><ns2:runReportReturn><ns2:reportBytes>" +
	       encoded +
	       "</ns2:reportBytes></ns2:runReportReturn></ns2:runReportResponse>"
	       "</soap:Body></soap:Envelope>";
}

std::string MakeReportXML(const std::string &escaped_rowset) {
	return "<DATA_DS><G_1><RESULT>" + escaped_rowset + "</RESULT></G_1></DATA_DS>";
}

//! Records what the adapter asked for and replays a canned answer.
struct Script {
	std::string response;
	//! Populated by the transport so assertions can inspect the request.
	std::vector<std::string> executed_sql;
	std::vector<FusionConfig> configs;
};

class FakeTransport : public FusionTransport {
public:
	FakeTransport(Script &script_p, FusionConfig config) : script(script_p) {
		script.configs.push_back(std::move(config));
	}

	std::string Execute(const std::string &sql, const RequestContext &) override {
		script.executed_sql.push_back(sql);
		return script.response;
	}

private:
	Script &script;
};

ScopedTransportFactory InstallFake(Script &script) {
	return ScopedTransportFactory(
	    [&script](const FusionConfig &config) { return std::make_shared<FakeTransport>(script, config); });
}

std::unique_ptr<duckdb::MaterializedQueryResult> RunQuery(Connection &connection, const std::string &sql) {
	auto result = connection.Query(sql);
	if (result->HasError()) {
		std::cerr << "query failed: " << result->GetError() << std::endl;
		std::abort();
	}
	return result;
}

const char *const QUERY = "SELECT * FROM oracle_fusion_wsdl_query('https://fusion.example.com/x?WSDL', 'user', "
                          "'secret', '/Custom/Financials/RP_ARB.xdo', 'SELECT NAME, CODE FROM FND_CURRENCIES_TL')";

void TestScanReturnsRows() {
	Script script;
	script.response = MakeSoapResponse(
	    MakeReportXML("&lt;ROWSET&gt;"
	                  "&lt;ROW&gt;&lt;NAME&gt;Alpha&lt;/NAME&gt;&lt;CODE&gt;A&lt;/CODE&gt;&lt;/ROW&gt;"
	                  "&lt;ROW&gt;&lt;NAME&gt;Beta&lt;/NAME&gt;&lt;CODE&gt;B&lt;/CODE&gt;&lt;/ROW&gt;"
	                  "&lt;/ROWSET&gt;"));
	auto installed = InstallFake(script);

	DuckDB db(nullptr);
	Connection connection(db);
	auto result = RunQuery(connection, QUERY);

	CHECK(result->RowCount() == 2);
	CHECK(result->ColumnCount() == 2);
	// Alphabetical, not SELECT order: today's behaviour, pinned so the coming fix is visible.
	CHECK(result->names[0] == "CODE");
	CHECK(result->names[1] == "NAME");
	CHECK(result->types[0] == duckdb::LogicalType::VARCHAR);
	CHECK(result->GetValue(1, 0).ToString() == "Alpha");
	CHECK(result->GetValue(0, 1).ToString() == "B");
}

void TestCredentialsAndSqlReachTheTransport() {
	Script script;
	script.response = MakeSoapResponse(MakeReportXML("&lt;ROWSET/&gt;"));
	auto installed = InstallFake(script);

	DuckDB db(nullptr);
	Connection connection(db);
	RunQuery(connection, QUERY);

	CHECK(script.configs.size() == 1);
	CHECK(script.configs[0].endpoint == "https://fusion.example.com/x?WSDL");
	CHECK(script.configs[0].username == "user");
	CHECK(script.configs[0].password == "secret");
	CHECK(script.configs[0].report_path == "/Custom/Financials/RP_ARB.xdo");
	CHECK(script.executed_sql.size() == 1);
	CHECK(script.executed_sql[0] == "SELECT NAME, CODE FROM FND_CURRENCIES_TL");
}

//! An empty report carries no schema, so the column list is guessed from the
//! SQL text. Pinned because the guess is naive and is scheduled for removal.
void TestEmptyResultDerivesColumnsFromSql() {
	Script script;
	script.response = MakeSoapResponse(MakeReportXML("&lt;ROWSET/&gt;"));
	auto installed = InstallFake(script);

	DuckDB db(nullptr);
	Connection connection(db);
	auto result = RunQuery(connection, QUERY);

	CHECK(result->RowCount() == 0);
	CHECK(result->ColumnCount() == 2);
	CHECK(result->names[0] == "NAME");
	CHECK(result->names[1] == "CODE");
}

void TestSelectStarWithEmptyResultFallsBackToSingleColumn() {
	Script script;
	script.response = MakeSoapResponse(MakeReportXML("&lt;ROWSET/&gt;"));
	auto installed = InstallFake(script);

	DuckDB db(nullptr);
	Connection connection(db);
	auto result = RunQuery(connection, "SELECT * FROM oracle_fusion_wsdl_query('https://h/x?WSDL', 'u', 'p', "
	                                   "'/r.xdo', 'SELECT * FROM DUAL')");

	CHECK(result->ColumnCount() == 1);
	CHECK(result->names[0] == "RESULT");
}

//! A SOAP fault currently yields zero rows rather than an error. That is the
//! behaviour being moved here unchanged; when it becomes an exception this test
//! should be inverted rather than deleted.
void TestSoapFaultCurrentlyYieldsNoRows() {
	Script script;
	script.response = "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\"><soap:Body>"
	                  "<soap:Fault><soap:Reason><soap:Text>ORA-00942: table or view does not exist</soap:Text>"
	                  "</soap:Reason></soap:Fault></soap:Body></soap:Envelope>";
	auto installed = InstallFake(script);

	DuckDB db(nullptr);
	Connection connection(db);
	auto result = RunQuery(connection, QUERY);

	CHECK(result->RowCount() == 0);
}

//! Missing columns are SQL NULL, not the empty string: dbms_xmlgen omits NULLs.
void TestMissingColumnBecomesEmptyString() {
	Script script;
	script.response = MakeSoapResponse(
	    MakeReportXML("&lt;ROWSET&gt;"
	                  "&lt;ROW&gt;&lt;NAME&gt;Alpha&lt;/NAME&gt;&lt;CODE&gt;A&lt;/CODE&gt;&lt;/ROW&gt;"
	                  "&lt;ROW&gt;&lt;NAME&gt;Beta&lt;/NAME&gt;&lt;/ROW&gt;"
	                  "&lt;/ROWSET&gt;"));
	auto installed = InstallFake(script);

	DuckDB db(nullptr);
	Connection connection(db);
	auto result = RunQuery(connection, QUERY);

	CHECK(result->RowCount() == 2);
	// Today the absent value is emitted as an empty string rather than NULL.
	CHECK(result->GetValue(0, 1).ToString().empty());
}

//! More rows than one vector, to exercise the chunking loop.
void TestScanEmitsMoreThanOneVector() {
	std::string rowset = "&lt;ROWSET&gt;";
	const int row_count = STANDARD_VECTOR_SIZE + 17;
	for (int i = 0; i < row_count; i++) {
		rowset += "&lt;ROW&gt;&lt;N&gt;" + std::to_string(i) + "&lt;/N&gt;&lt;/ROW&gt;";
	}
	rowset += "&lt;/ROWSET&gt;";

	Script script;
	script.response = MakeSoapResponse(MakeReportXML(rowset));
	auto installed = InstallFake(script);

	DuckDB db(nullptr);
	Connection connection(db);
	auto result = RunQuery(connection, QUERY);

	CHECK(result->RowCount() == static_cast<duckdb::idx_t>(row_count));
	CHECK(result->GetValue(0, 0).ToString() == "0");
	CHECK(result->GetValue(0, row_count - 1).ToString() == std::to_string(row_count - 1));
}

void TestTransportFailureSurfacesAsQueryError() {
	struct ThrowingTransport : FusionTransport {
		std::string Execute(const std::string &, const RequestContext &) override {
			throw std::runtime_error("SOAP request failed: Could not resolve host");
		}
	};
	ScopedTransportFactory installed(
	    [](const FusionConfig &) { return std::make_shared<ThrowingTransport>(); });

	DuckDB db(nullptr);
	Connection connection(db);
	auto result = connection.Query(QUERY);

	CHECK(result->HasError());
	CHECK(result->GetError().find("Could not resolve host") != std::string::npos);
}

struct TestCase {
	const char *name;
	void (*run)();
};

const TestCase TESTS[] = {
    {"scan returns rows", TestScanReturnsRows},
    {"credentials and sql reach the transport", TestCredentialsAndSqlReachTheTransport},
    {"empty result derives columns from sql", TestEmptyResultDerivesColumnsFromSql},
    {"select star with empty result falls back", TestSelectStarWithEmptyResultFallsBackToSingleColumn},
    {"soap fault currently yields no rows", TestSoapFaultCurrentlyYieldsNoRows},
    {"missing column becomes empty string", TestMissingColumnBecomesEmptyString},
    {"scan emits more than one vector", TestScanEmitsMoreThanOneVector},
    {"transport failure surfaces as query error", TestTransportFailureSurfacesAsQueryError},
};

} // namespace

int main() {
	for (const auto &test : TESTS) {
		std::cout << "  " << test.name << std::endl;
		test.run();
	}
	std::cout << sizeof(TESTS) / sizeof(TESTS[0]) << " adapter tests passed" << std::endl;
	return 0;
}
