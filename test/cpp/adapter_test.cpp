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

//! A database with one usable secret, which is what most tests want.
void CreateSecret(Connection &connection, const char *name = "fusion") {
	auto result = connection.Query(std::string("CREATE SECRET ") + name +
	                               " (TYPE oracle_fusion, "
	                               "ENDPOINT 'https://fusion.example.com/xmlpserver/services/"
	                               "ExternalReportWSSService?WSDL', "
	                               "REPORT_PATH '/Custom/Financials/RP_ARB.xdo', "
	                               "USERNAME 'analyst', PASSWORD 'hunter2')");
	if (result->HasError()) {
		std::cerr << "CREATE SECRET failed: " << result->GetError() << std::endl;
		std::abort();
	}
}

std::unique_ptr<duckdb::MaterializedQueryResult> RunQuery(Connection &connection, const std::string &sql) {
	auto result = connection.Query(sql);
	if (result->HasError()) {
		std::cerr << "query failed: " << result->GetError() << std::endl;
		std::abort();
	}
	return result;
}

const char *const QUERY = "SELECT * FROM oracle_fusion_query('SELECT NAME, CODE FROM FND_CURRENCIES_TL')";

const char *const TWO_ROWS = "&lt;ROWSET&gt;"
                             "&lt;ROW&gt;&lt;NAME&gt;Alpha&lt;/NAME&gt;&lt;CODE&gt;A&lt;/CODE&gt;&lt;/ROW&gt;"
                             "&lt;ROW&gt;&lt;NAME&gt;Beta&lt;/NAME&gt;&lt;CODE&gt;B&lt;/CODE&gt;&lt;/ROW&gt;"
                             "&lt;/ROWSET&gt;";

void TestScanReturnsRowsInSelectOrder() {
	Script script;
	script.response = MakeSoapResponse(MakeReportXML(TWO_ROWS));
	auto installed = InstallFake(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto result = RunQuery(connection, QUERY);

	CHECK(result->RowCount() == 2);
	CHECK(result->ColumnCount() == 2);
	// Document order, i.e. SELECT order. This used to come back alphabetical.
	CHECK(result->names[0] == "NAME");
	CHECK(result->names[1] == "CODE");
	CHECK(result->GetValue(0, 0).ToString() == "Alpha");
	CHECK(result->GetValue(1, 1).ToString() == "B");
}

void TestSecretSuppliesTheConnection() {
	Script script;
	script.response = MakeSoapResponse(MakeReportXML(TWO_ROWS));
	auto installed = InstallFake(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	RunQuery(connection, QUERY);

	CHECK(script.configs.size() == 1);
	CHECK(script.configs[0].endpoint ==
	      "https://fusion.example.com/xmlpserver/services/ExternalReportWSSService?WSDL");
	CHECK(script.configs[0].username == "analyst");
	CHECK(script.configs[0].password == "hunter2");
	CHECK(script.configs[0].report_path == "/Custom/Financials/RP_ARB.xdo");
	CHECK(script.executed_sql.size() == 1);
	CHECK(script.executed_sql[0] == "SELECT NAME, CODE FROM FND_CURRENCIES_TL");
}

//! The password must not be readable through duckdb_secrets(). Note this hides
//! it from the view only: a PERSISTENT secret is still written to disk in the
//! clear, which is a documentation matter rather than something to assert here.
void TestSecretRedactsCredentials() {
	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);

	auto result = RunQuery(connection, "SELECT secret_string FROM duckdb_secrets() WHERE name = 'fusion'");
	CHECK(result->RowCount() == 1);
	const auto rendered = result->GetValue(0, 0).ToString();
	CHECK(rendered.find("hunter2") == std::string::npos);
	CHECK(rendered.find("redacted") != std::string::npos);
	// Non-secret fields stay visible, otherwise the view is useless.
	CHECK(rendered.find("analyst") != std::string::npos);
}

void TestNamedParametersOverrideTheSecret() {
	Script script;
	script.response = MakeSoapResponse(MakeReportXML(TWO_ROWS));
	auto installed = InstallFake(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	RunQuery(connection, "SELECT * FROM oracle_fusion_query('SELECT NAME, CODE FROM T', "
	                     "report_path := '/Custom/Other.xdo', username := 'override')");

	CHECK(script.configs.size() == 1);
	CHECK(script.configs[0].report_path == "/Custom/Other.xdo");
	CHECK(script.configs[0].username == "override");
	// Untouched fields still come from the secret.
	CHECK(script.configs[0].password == "hunter2");
}

//! A SOAP fault used to yield zero rows, so a permissions problem or a typo in
//! a table name was indistinguishable from a query that matched nothing.
void TestSoapFaultBecomesAnError() {
	Script script;
	script.response = "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\"><soap:Body>"
	                  "<soap:Fault><faultstring>oracle.xdo.XDOException: ORA-00942: table or view does not "
	                  "exist</faultstring></soap:Fault></soap:Body></soap:Envelope>";
	auto installed = InstallFake(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto result = connection.Query(QUERY);

	CHECK(result->HasError());
	CHECK(result->GetError().find("ORA-00942") != std::string::npos);
	// The failing statement is echoed, since the error is about that statement.
	CHECK(result->GetError().find("FND_CURRENCIES_TL") != std::string::npos);
}

void TestHtmlLoginPageBecomesAnError() {
	Script script;
	script.response = "<html><head><title>Oracle Fusion Sign In</title></head><body/></html>";
	auto installed = InstallFake(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto result = connection.Query(QUERY);

	CHECK(result->HasError());
	CHECK(result->GetError().find("Sign In") != std::string::npos);
}

//! An empty result carries no schema. Guessing column names from the SQL text,
//! which is what this used to do, silently produced a wrong schema for any
//! query with a function call or a subquery in its select list.
void TestEmptyResultIsAnErrorRatherThanAGuessedSchema() {
	Script script;
	script.response = MakeSoapResponse(MakeReportXML("&lt;ROWSET/&gt;"));
	auto installed = InstallFake(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto result = connection.Query(QUERY);

	CHECK(result->HasError());
	CHECK(result->GetError().find("no rows") != std::string::npos);
}

//! dbms_xmlgen omits NULL elements, so an absent column is NULL. It used to
//! arrive as an empty string, which is a different value.
void TestMissingColumnBecomesNull() {
	Script script;
	script.response = MakeSoapResponse(
	    MakeReportXML("&lt;ROWSET&gt;"
	                  "&lt;ROW&gt;&lt;NAME&gt;Alpha&lt;/NAME&gt;&lt;CODE&gt;A&lt;/CODE&gt;&lt;/ROW&gt;"
	                  "&lt;ROW&gt;&lt;NAME&gt;Beta&lt;/NAME&gt;&lt;CODE&gt;&lt;/CODE&gt;&lt;/ROW&gt;"
	                  "&lt;ROW&gt;&lt;NAME&gt;Gamma&lt;/NAME&gt;&lt;/ROW&gt;"
	                  "&lt;/ROWSET&gt;"));
	auto installed = InstallFake(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto result = RunQuery(connection, QUERY);

	CHECK(result->RowCount() == 3);
	CHECK(!result->GetValue(1, 0).IsNull());          // present, "A"
	CHECK(!result->GetValue(1, 1).IsNull());          // present but empty
	CHECK(result->GetValue(1, 1).ToString().empty()); //   -> empty string
	CHECK(result->GetValue(1, 2).IsNull());           // absent -> NULL
}

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
	CreateSecret(connection);
	auto result = RunQuery(connection, "SELECT * FROM oracle_fusion_query('SELECT N FROM BIG')");

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
	ScopedTransportFactory installed([](const FusionConfig &) { return std::make_shared<ThrowingTransport>(); });

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto result = connection.Query(QUERY);

	CHECK(result->HasError());
	CHECK(result->GetError().find("Could not resolve host") != std::string::npos);
}

void TestMissingSecretIsExplained() {
	DuckDB db(nullptr);
	Connection connection(db);
	auto result = connection.Query(QUERY);

	CHECK(result->HasError());
	CHECK(result->GetError().find("CREATE SECRET") != std::string::npos);
}

//! Picking one of several secrets by chance would send credentials to whichever
//! instance happened to sort first, so it is reported instead.
void TestAmbiguousSecretIsReported() {
	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection, "dev");
	CreateSecret(connection, "prod");

	auto result = connection.Query(QUERY);
	CHECK(result->HasError());
	CHECK(result->GetError().find("dev") != std::string::npos);
	CHECK(result->GetError().find("prod") != std::string::npos);
	CHECK(result->GetError().find("secret :=") != std::string::npos);
}

void TestNamedSecretIsSelected() {
	Script script;
	script.response = MakeSoapResponse(MakeReportXML(TWO_ROWS));
	auto installed = InstallFake(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection, "dev");
	CreateSecret(connection, "prod");
	RunQuery(connection, "SELECT * FROM oracle_fusion_query('SELECT NAME, CODE FROM T', secret := 'prod')");

	CHECK(script.configs.size() == 1);
}

void TestUnknownSecretIsReported() {
	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);

	auto result = connection.Query("SELECT * FROM oracle_fusion_query('SELECT 1 FROM DUAL', secret := 'nope')");
	CHECK(result->HasError());
	CHECK(result->GetError().find("nope") != std::string::npos);
}

void TestFetchSizeIsValidated() {
	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);

	auto result = connection.Query("SELECT * FROM oracle_fusion_query('SELECT 1 FROM DUAL', fetch_size := 999999)");
	CHECK(result->HasError());
	CHECK(result->GetError().find("fetch_size") != std::string::npos);
}

//! The removed positional function explains the migration rather than saying
//! "function does not exist", which reads as a broken install.
void TestRemovedFunctionExplainsMigration() {
	DuckDB db(nullptr);
	Connection connection(db);

	auto result = connection.Query("SELECT * FROM oracle_fusion_wsdl_query('https://h/x?WSDL', 'u', 'p', "
	                               "'/r.xdo', 'SELECT 1 FROM DUAL')");
	CHECK(result->HasError());
	CHECK(result->GetError().find("oracle_fusion_query") != std::string::npos);
	CHECK(result->GetError().find("CREATE SECRET") != std::string::npos);
}

//! The browser provider is registered so the error names the missing feature
//! instead of reading like a typo in the provider name.
void TestBrowserProviderReportsNotImplemented() {
	DuckDB db(nullptr);
	Connection connection(db);

	auto result = connection.Query("CREATE SECRET sso (TYPE oracle_fusion, PROVIDER browser, "
	                               "ENDPOINT 'https://h/x?WSDL', REPORT_PATH '/r.xdo')");
	CHECK(result->HasError());
	CHECK(result->GetError().find("not implemented yet") != std::string::npos);
}

struct TestCase {
	const char *name;
	void (*run)();
};

const TestCase TESTS[] = {
    {"scan returns rows in select order", TestScanReturnsRowsInSelectOrder},
    {"secret supplies the connection", TestSecretSuppliesTheConnection},
    {"secret redacts credentials", TestSecretRedactsCredentials},
    {"named parameters override the secret", TestNamedParametersOverrideTheSecret},
    {"soap fault becomes an error", TestSoapFaultBecomesAnError},
    {"html login page becomes an error", TestHtmlLoginPageBecomesAnError},
    {"empty result is an error", TestEmptyResultIsAnErrorRatherThanAGuessedSchema},
    {"missing column becomes null", TestMissingColumnBecomesNull},
    {"scan emits more than one vector", TestScanEmitsMoreThanOneVector},
    {"transport failure surfaces as query error", TestTransportFailureSurfacesAsQueryError},
    {"missing secret is explained", TestMissingSecretIsExplained},
    {"ambiguous secret is reported", TestAmbiguousSecretIsReported},
    {"named secret is selected", TestNamedSecretIsSelected},
    {"unknown secret is reported", TestUnknownSecretIsReported},
    {"fetch size is validated", TestFetchSizeIsValidated},
    {"removed function explains migration", TestRemovedFunctionExplainsMigration},
    {"browser provider reports not implemented", TestBrowserProviderReportsNotImplemented},
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
