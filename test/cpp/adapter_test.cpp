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

#include <algorithm>
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
	// Paging is on by default, so the statement reaches Fusion with the row
	// limiting clause appended to it.
	CHECK(script.executed_sql[0] == "SELECT NAME, CODE FROM FND_CURRENCIES_TL "
	                                "OFFSET 0 ROWS FETCH NEXT 500 ROWS ONLY");
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

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------

//! Serves a table of rows, honouring the OFFSET/FETCH the adapter wrote into
//! the statement -- so the number of requests is a real observation, not a
//! rehearsal of the code under test.
class PagingTransport : public FusionTransport {
public:
	PagingTransport(Script &script_p, int total_rows_p) : script(script_p), total_rows(total_rows_p) {
	}

	std::string Execute(const std::string &sql, const RequestContext &) override {
		script.executed_sql.push_back(sql);

		int offset = 0;
		int limit = total_rows;
		const auto offset_at = sql.find(" OFFSET ");
		if (offset_at != std::string::npos) {
			offset = std::atoi(sql.c_str() + offset_at + 8);
			const auto fetch_at = sql.find(" FETCH NEXT ");
			CHECK(fetch_at != std::string::npos);
			limit = std::atoi(sql.c_str() + fetch_at + 12);
		}

		std::string rowset = "&lt;ROWSET&gt;";
		for (int i = offset; i < std::min(offset + limit, total_rows); i++) {
			rowset += "&lt;ROW&gt;&lt;N&gt;" + std::to_string(i) + "&lt;/N&gt;&lt;/ROW&gt;";
		}
		rowset += "&lt;/ROWSET&gt;";
		return MakeSoapResponse(MakeReportXML(rowset));
	}

private:
	Script &script;
	int total_rows;
};

ScopedTransportFactory InstallPaging(Script &script, int total_rows) {
	return ScopedTransportFactory(
	    [&script, total_rows](const FusionConfig &) { return std::make_shared<PagingTransport>(script, total_rows); });
}

//! 1637 rows at 500 per page is three full pages and a short one, and the short
//! page is what tells the scan to stop -- so exactly four requests, not five.
void TestPagingFetchesEveryRowInExactlyTheRightNumberOfRequests() {
	Script script;
	auto installed = InstallPaging(script, 1637);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto result = RunQuery(connection, "SELECT * FROM oracle_fusion_query('SELECT N FROM BIG', fetch_size := 500)");

	CHECK(result->RowCount() == 1637);
	CHECK(script.executed_sql.size() == 4);
	CHECK(result->GetValue(0, 0).ToString() == "0");
	CHECK(result->GetValue(0, 1636).ToString() == "1636");

	// Offsets advance by the page size, and the first page starts at zero.
	CHECK(script.executed_sql[0].find("OFFSET 0 ROWS FETCH NEXT 500 ROWS ONLY") != std::string::npos);
	CHECK(script.executed_sql[1].find("OFFSET 500 ROWS") != std::string::npos);
	CHECK(script.executed_sql[3].find("OFFSET 1500 ROWS") != std::string::npos);
}

//! A result that fits in one page must not cost a second request just to
//! discover there is nothing more.
void TestShortFirstPageCostsOneRequest() {
	Script script;
	auto installed = InstallPaging(script, 3);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto result = RunQuery(connection, "SELECT * FROM oracle_fusion_query('SELECT N FROM SMALL', fetch_size := 500)");

	CHECK(result->RowCount() == 3);
	CHECK(script.executed_sql.size() == 1);
}

//! An exactly-full last page is indistinguishable from a full one, so one extra
//! request is unavoidable -- but only one, and it must come back empty rather
//! than erroring on the empty schema.
void TestExactlyFullPageCostsOneExtraRequest() {
	Script script;
	auto installed = InstallPaging(script, 20);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto result = RunQuery(connection, "SELECT * FROM oracle_fusion_query('SELECT N FROM T', fetch_size := 10)");

	CHECK(result->RowCount() == 20);
	CHECK(script.executed_sql.size() == 3);
}

void TestPagingCanBeDisabled() {
	Script script;
	auto installed = InstallPaging(script, 1637);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto result = RunQuery(connection, "SELECT * FROM oracle_fusion_query('SELECT N FROM BIG', fetch_size := 0)");

	CHECK(result->RowCount() == 1637);
	CHECK(script.executed_sql.size() == 1);
	CHECK(script.executed_sql[0].find("OFFSET") == std::string::npos);
}

//! The author already limited the result, so wrapping ours around theirs would
//! change which rows come back.
void TestStatementWithItsOwnLimitIsNotRewritten() {
	Script script;
	auto installed = InstallPaging(script, 1637);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto result = RunQuery(connection, "SELECT * FROM oracle_fusion_query("
	                                   "'SELECT N FROM BIG OFFSET 100 ROWS FETCH NEXT 5 ROWS ONLY', fetch_size := 500)");

	CHECK(script.executed_sql.size() == 1);
	CHECK(result->RowCount() == 5);
	CHECK(result->GetValue(0, 0).ToString() == "100");
}

// ---------------------------------------------------------------------------
// Type inference
// ---------------------------------------------------------------------------

void TestTypesAreInferredFromTheFirstPage() {
	Script script;
	script.response = MakeSoapResponse(MakeReportXML(
	    "&lt;ROWSET&gt;&lt;ROW&gt;"
	    "&lt;ID&gt;42&lt;/ID&gt;&lt;AMOUNT&gt;1.50&lt;/AMOUNT&gt;&lt;WHEN&gt;2024-01-31&lt;/WHEN&gt;"
	    "&lt;BIG&gt;123456789012&lt;/BIG&gt;&lt;CODE&gt;00123&lt;/CODE&gt;&lt;NAME&gt;Alpha&lt;/NAME&gt;"
	    "&lt;/ROW&gt;&lt;/ROWSET&gt;"));
	auto installed = InstallFake(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto result = RunQuery(connection, "SELECT * FROM oracle_fusion_query('SELECT … FROM T')");

	CHECK(result->types[0] == duckdb::LogicalType::INTEGER);
	CHECK(result->types[1].id() == duckdb::LogicalTypeId::DECIMAL);
	CHECK(result->types[2] == duckdb::LogicalType::DATE);
	CHECK(result->types[3] == duckdb::LogicalType::BIGINT);
	// A leading zero means an identifier, not a number.
	CHECK(result->types[4] == duckdb::LogicalType::VARCHAR);
	CHECK(result->types[5] == duckdb::LogicalType::VARCHAR);

	CHECK(result->GetValue(0, 0).ToString() == "42");
	CHECK(result->GetValue(4, 0).ToString() == "00123");
}

void TestAllVarcharDisablesInference() {
	Script script;
	script.response = MakeSoapResponse(
	    MakeReportXML("&lt;ROWSET&gt;&lt;ROW&gt;&lt;ID&gt;42&lt;/ID&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));
	auto installed = InstallFake(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto result =
	    RunQuery(connection, "SELECT * FROM oracle_fusion_query('SELECT ID FROM T', all_varchar := true)");

	CHECK(result->types[0] == duckdb::LogicalType::VARCHAR);
}

//! The type is a guess from a sample, so a later row can disagree. Such a value
//! becomes NULL rather than failing the query: one odd row in a million should
//! not cost the user the other 999,999.
void TestValueThatContradictsTheInferredTypeBecomesNull() {
	Script script;
	std::string rowset = "&lt;ROWSET&gt;";
	// The first 20 rows are what inference sees, and they are all integers.
	for (int i = 0; i < 20; i++) {
		rowset += "&lt;ROW&gt;&lt;ID&gt;" + std::to_string(i) + "&lt;/ID&gt;&lt;/ROW&gt;";
	}
	rowset += "&lt;ROW&gt;&lt;ID&gt;not a number&lt;/ID&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;";
	script.response = MakeSoapResponse(MakeReportXML(rowset));
	auto installed = InstallFake(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto result = RunQuery(connection, "SELECT * FROM oracle_fusion_query('SELECT ID FROM T')");

	CHECK(result->types[0] == duckdb::LogicalType::INTEGER);
	CHECK(result->RowCount() == 21);
	CHECK(!result->GetValue(0, 19).IsNull());
	CHECK(result->GetValue(0, 20).IsNull());
}

//! A typed column can still be NULL, and an empty element in a typed column is
//! NULL too -- there is no integer spelled "".
void TestNullsInTypedColumns() {
	Script script;
	script.response = MakeSoapResponse(
	    MakeReportXML("&lt;ROWSET&gt;"
	                  "&lt;ROW&gt;&lt;ID&gt;1&lt;/ID&gt;&lt;/ROW&gt;"
	                  "&lt;ROW&gt;&lt;ID&gt;&lt;/ID&gt;&lt;/ROW&gt;"
	                  "&lt;ROW&gt;&lt;OTHER&gt;x&lt;/OTHER&gt;&lt;/ROW&gt;"
	                  "&lt;/ROWSET&gt;"));
	auto installed = InstallFake(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto result = RunQuery(connection, "SELECT * FROM oracle_fusion_query('SELECT ID, OTHER FROM T')");

	CHECK(result->types[0] == duckdb::LogicalType::INTEGER);
	CHECK(result->GetValue(0, 0).ToString() == "1");
	CHECK(result->GetValue(0, 1).IsNull()); // present but empty
	CHECK(result->GetValue(0, 2).IsNull()); // absent
}

//! The statement that reaches Fusion is normalised, so a hint written by the
//! author still arrives -- it is lexically a comment, and a careless stripper
//! would drop the plan it asks for.
void TestHintSurvivesToTheWire() {
	Script script;
	script.response = MakeSoapResponse(
	    MakeReportXML("&lt;ROWSET&gt;&lt;ROW&gt;&lt;N&gt;1&lt;/N&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));
	auto installed = InstallFake(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	RunQuery(connection, "SELECT * FROM oracle_fusion_query("
	                     "'SELECT /*+ FIRST_ROWS(1000) */ N FROM T /* dropped */', fetch_size := 0)");

	CHECK(script.executed_sql.size() == 1);
	CHECK(script.executed_sql[0].find("/*+ FIRST_ROWS(1000) */") != std::string::npos);
	CHECK(script.executed_sql[0].find("dropped") == std::string::npos);
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
    {"paging fetches every row in exactly the right number of requests", TestPagingFetchesEveryRowInExactlyTheRightNumberOfRequests},
    {"short first page costs one request", TestShortFirstPageCostsOneRequest},
    {"exactly full page costs one extra request", TestExactlyFullPageCostsOneExtraRequest},
    {"paging can be disabled", TestPagingCanBeDisabled},
    {"statement with its own limit is not rewritten", TestStatementWithItsOwnLimitIsNotRewritten},
    {"types are inferred from the first page", TestTypesAreInferredFromTheFirstPage},
    {"all_varchar disables inference", TestAllVarcharDisablesInference},
    {"contradicting value becomes null", TestValueThatContradictsTheInferredTypeBecomesNull},
    {"nulls in typed columns", TestNullsInTypedColumns},
    {"hint survives to the wire", TestHintSurvivesToTheWire},
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
