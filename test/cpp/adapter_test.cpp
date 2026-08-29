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

#include "ofquack/metadata_cache.hpp"
#include "ofquack/metadata_fetch.hpp"
#include "ofquack/metadata_queries.hpp"
#include "ofquack/fusion_catalog.hpp"
#include "ofquack/token_cache.hpp"
#include "ofquack/errors.hpp"
#include "ofquack/transport.hpp"
#include "fusion_scanner_extension.hpp"

#include "base64.h"
#include "duckdb.hpp"

#include <algorithm>
#include <set>
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

//! True when a paged statement is asking for anything past the first page.
//!
//! Every fake here has to honour this. A scan ends on an empty page, not on a
//! short one, so a fake that served the same rows whatever offset it was given
//! would never let one finish -- which is exactly the server behaviour the scan
//! now refuses.
bool AsksForALaterPage(const std::string &sql) {
	// Two paging schemes are in play: the table listing seeks from the last
	// name, and everything else offsets. A request is for a later page if it
	// carries the seek predicate, or an offset past zero.
	if (sql.find("t.table_name > ") != std::string::npos) {
		return true;
	}
	const auto at = sql.find("OFFSET ");
	return at != std::string::npos && sql.compare(at + 7, 1, "0") != 0;
}

class FakeTransport : public FusionTransport {
public:
	FakeTransport(Script &script_p, FusionConfig config) : script(script_p) {
		script.configs.push_back(std::move(config));
	}

	std::string Execute(const std::string &sql, const RequestContext &) override {
		script.executed_sql.push_back(sql);
		if (AsksForALaterPage(sql)) {
			return MakeSoapResponse(MakeReportXML("&lt;ROWSET/&gt;"));
		}
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
	// Two requests: the page, and the one that confirms nothing follows it.
	CHECK(script.executed_sql.size() == 2);
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

//! A secret naming only the instance is completed to the service URL. The
//! path is the same on every Fusion instance, and getting it slightly wrong
//! sends the POST to the application, which answers with its home page --
//! a failure several layers removed from its cause.
void TestBareHostEndpointIsCompleted() {
	Script script;
	script.response = MakeSoapResponse(MakeReportXML(TWO_ROWS));
	auto installed = InstallFake(script);

	DuckDB db(nullptr);
	Connection connection(db);
	auto created = connection.Query("CREATE SECRET host_only (TYPE oracle_fusion, "
	                                "ENDPOINT 'https://fa.example.com', REPORT_PATH '/Custom/RP_ARB.xdo', "
	                                "USERNAME 'u', PASSWORD 'p')");
	CHECK(!created->HasError());

	RunQuery(connection, "SELECT * FROM oracle_fusion_query('SELECT NAME, CODE FROM T', secret := 'host_only')");

	CHECK(script.configs.size() == 1);
	CHECK(script.configs[0].endpoint ==
	      "https://fa.example.com/xmlpserver/services/ExternalReportWSSService?WSDL");
}

//! An endpoint that already names the service is left exactly as written.
void TestFullEndpointIsLeftAlone() {
	Script script;
	script.response = MakeSoapResponse(MakeReportXML(TWO_ROWS));
	auto installed = InstallFake(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	RunQuery(connection, "SELECT * FROM oracle_fusion_query('SELECT NAME, CODE FROM T')");

	CHECK(script.configs[0].endpoint ==
	      "https://fusion.example.com/xmlpserver/services/ExternalReportWSSService?WSDL");
}

//! Defined with the metadata tests below; the cache is a process-wide
//! singleton, so a test asserting a fetch must start from an empty one.
void ResetCache();

//! A metadata query that gets something other than a report must say what it
//! got. "Missing SOAP Envelope" describes the shape of a response without
//! saying what the response was, and the answer is usually in its first line.
void TestMetadataFailureShowsWhatArrived() {
	ResetCache();
	struct SignInPageTransport : FusionTransport {
		std::string Execute(const std::string &, const RequestContext &) override {
			// A sign-in page that parses as XML: no Envelope, no <html> prefix,
			// so neither the HTML check nor the fault decoder catches it.
			return "<?xml version=\"1.0\"?><page><title>Oracle Applications Cloud Sign In</title></page>";
		}
	};
	ScopedTransportFactory installed([](const FusionConfig &) { return std::make_shared<SignInPageTransport>(); });

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto result = connection.Query("SELECT * FROM oracle_fusion_tables()");

	CHECK(result->HasError());
	const auto message = result->GetError();
	// Enough of the response to recognise it.
	CHECK(message.find("Sign In") != std::string::npos);
	CHECK(message.find("response began") != std::string::npos);
}

//! A secret with no username and no browser provider cannot authenticate at
//! all. Sending an empty Basic credential and reporting Fusion's 401 would
//! blame the password, when the mistake is nearly always the mode: an instance
//! behind single sign-on has no password to give.
void TestSecretWithNoCredentialNamesBothPossibilities() {
	Script script;
	auto installed = InstallFake(script);

	DuckDB db(nullptr);
	Connection connection(db);
	auto created = connection.Query("CREATE SECRET no_creds (TYPE oracle_fusion, "
	                                "ENDPOINT 'https://plain.example.com/x?WSDL', REPORT_PATH '/r.xdo')");
	CHECK(!created->HasError());

	auto result = connection.Query("SELECT * FROM oracle_fusion_query('SELECT 1 FROM DUAL', secret := 'no_creds')");
	CHECK(result->HasError());
	CHECK(result->GetError().find("USERNAME") != std::string::npos);
	CHECK(result->GetError().find("PROVIDER browser") != std::string::npos);
	// Nothing was sent: an empty credential never reaches Fusion.
	CHECK(script.executed_sql.empty());
}

//! An unknown AUTH is a typo worth reporting, and the message names what is
//! actually accepted.
void TestUnknownAuthModeIsReported() {
	Script script;
	auto installed = InstallFake(script);

	DuckDB db(nullptr);
	Connection connection(db);
	auto created = connection.Query("CREATE SECRET odd_auth (TYPE oracle_fusion, ENDPOINT 'https://h/x?WSDL', "
	                                "REPORT_PATH '/r.xdo', AUTH 'kerberos')");
	CHECK(!created->HasError());

	auto result = connection.Query("SELECT * FROM oracle_fusion_query('SELECT 1 FROM DUAL', secret := 'odd_auth')");
	CHECK(result->HasError());
	CHECK(result->GetError().find("kerberos") != std::string::npos);
	CHECK(result->GetError().find("basic") != std::string::npos);
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
	CHECK(result->GetValue(0, 0).ToString() == "0");
	CHECK(result->GetValue(0, 1636).ToString() == "1636");

	// Six: the schema page, the same page again under the ordering that paging
	// needs, three more pages, and the empty one that ends the scan.
	CHECK(script.executed_sql.size() == 6);
	// Offsets advance by the page size, and the first page starts at zero.
	CHECK(script.executed_sql[0].find("OFFSET 0 ROWS FETCH NEXT 500 ROWS ONLY") != std::string::npos);
	CHECK(script.executed_sql[1].find("OFFSET 0 ROWS FETCH NEXT 500 ROWS ONLY") != std::string::npos);
	CHECK(script.executed_sql[2].find("OFFSET 500 ROWS") != std::string::npos);
	CHECK(script.executed_sql[4].find("OFFSET 1500 ROWS") != std::string::npos);
	CHECK(script.executed_sql[5].find("OFFSET 1637 ROWS") != std::string::npos);
}

//! A result that fits in one page still costs one request to establish that it
//! does. A short page is not proof of the end: BI Publisher truncates a
//! response that grows too large without saying so, and the truncated page
//! looks exactly like the last one.
void TestShortFirstPageIsConfirmed() {
	Script script;
	auto installed = InstallPaging(script, 3);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto result = RunQuery(connection, "SELECT * FROM oracle_fusion_query('SELECT N FROM SMALL', fetch_size := 500)");

	CHECK(result->RowCount() == 3);
	CHECK(script.executed_sql.size() == 2);
	CHECK(script.executed_sql[1].find("OFFSET 3 ROWS") != std::string::npos);
	// The confirming request found nothing, so the ordering was never needed
	// and the page fetched during bind was kept as it was.
	CHECK(script.executed_sql[0].find("ORDER BY") == std::string::npos);
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
	// The schema page, the ordered retake of it, the second page, and the empty
	// one after it.
	CHECK(script.executed_sql.size() == 4);
}

//! Each page is a separate execution of the statement, and Oracle owes no two
//! of them the same row order. Paging an unordered statement therefore returns
//! a sample of the result rather than the result, and every page looks right.
void TestPagedStatementIsOrdered() {
	Script script;
	auto installed = InstallPaging(script, 1200);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto result = RunQuery(connection, "SELECT * FROM oracle_fusion_query('SELECT N FROM BIG', fetch_size := 500)");

	CHECK(result->RowCount() == 1200);
	// The first request is the one bind makes to learn the schema, and the
	// column count is not known before it comes back -- so it is the only one
	// without the ordering, and it is taken again with it.
	CHECK(script.executed_sql[0].find("ORDER BY") == std::string::npos);
	for (size_t i = 1; i < script.executed_sql.size(); i++) {
		CHECK(script.executed_sql[i].find("SELECT * FROM (SELECT N FROM BIG) ORDER BY 1 OFFSET") !=
		      std::string::npos);
	}
}

//! An author who wrote an ORDER BY has already said how the rows are to be
//! ordered. Wrapping ours around theirs would sort the result twice and cost a
//! request to re-read a page that was never wrong.
void TestStatementWithItsOwnOrderIsNotWrapped() {
	Script script;
	auto installed = InstallPaging(script, 1200);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto result =
	    RunQuery(connection, "SELECT * FROM oracle_fusion_query('SELECT N FROM BIG ORDER BY N', fetch_size := 500)");

	CHECK(result->RowCount() == 1200);
	// Three pages and the empty one after them; no retake of the first.
	CHECK(script.executed_sql.size() == 4);
	for (const auto &sql : script.executed_sql) {
		CHECK(sql.find("SELECT * FROM (") == std::string::npos);
	}
}

//! Serves a four-column result whose third column is a CLOB: any ORDER BY
//! that names position 3 is refused with ORA-00932, exactly as Oracle does.
//! Probes -- one row, an ORDER BY, no OFFSET -- are answered with a row.
class ClobTransport : public FusionTransport {
public:
	explicit ClobTransport(Script &script_p) : script(script_p) {
	}

	std::string Execute(const std::string &sql, const RequestContext &) override {
		script.executed_sql.push_back(sql);
		if (sql.find("WHERE ROWNUM <= 1") != std::string::npos) {
			probes++;
		}
		const auto order_at = sql.find(" ORDER BY ");
		if (order_at != std::string::npos) {
			// The positions between ORDER BY and whatever follows them.
			auto list = sql.substr(order_at + 10);
			list = list.substr(0, list.find(" OFFSET"));
			for (size_t at = 0; at < list.size();) {
				const auto comma = list.find(',', at);
				const auto token = list.substr(at, comma == std::string::npos ? std::string::npos : comma - at);
				if (std::atoi(token.c_str()) == 3) {
					throw ofquack::PermanentError("Oracle Fusion rejected the request: ORA-00932: inconsistent "
					                              "datatypes: expected - got CLOB");
				}
				at = comma == std::string::npos ? list.size() : comma + 1;
			}
		}
		if (sql.find("WHERE ROWNUM <= 1") != std::string::npos) {
			return MakeSoapResponse(MakeReportXML("&lt;ROWSET&gt;&lt;ROW&gt;&lt;ID&gt;0&lt;/ID&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));
		}
		int offset = 0;
		const auto at = sql.find(" OFFSET ");
		if (at != std::string::npos) {
			offset = std::atoi(sql.c_str() + at + 8);
		}
		std::string rowset = "&lt;ROWSET&gt;";
		for (int i = offset; i < std::min(offset + 10, 25); i++) {
			rowset += "&lt;ROW&gt;&lt;ID&gt;" + std::to_string(i) +
			          "&lt;/ID&gt;&lt;NAME&gt;n&lt;/NAME&gt;&lt;TEXT&gt;body&lt;/TEXT&gt;&lt;STATUS&gt;A&lt;/STATUS&gt;&lt;/ROW&gt;";
		}
		return MakeSoapResponse(MakeReportXML(rowset + "&lt;/ROWSET&gt;"));
	}

	int probes = 0;

private:
	Script &script;
};

//! FND_VIEWS has a CLOB, and "ORDER BY 1, 2, ..., 18" over it is ORA-00932.
//! Oracle SQL has no function that will say which column is the CLOB (DUMP
//! refuses it too), so the scan finds out by asking about halves of the
//! column list, on one row each, and then orders by the rest.
void TestOrderSkipsColumnsOracleRefusesToSort() {
	Script script;
	std::shared_ptr<ClobTransport> transport;
	ScopedTransportFactory installed([&](const FusionConfig &) {
		transport = std::make_shared<ClobTransport>(script);
		return transport;
	});

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto result = RunQuery(
	    connection, "SELECT * FROM oracle_fusion_query('SELECT ID, NAME, TEXT, STATUS FROM V', fetch_size := 10)");

	CHECK(result->RowCount() == 25);
	// Halving over four columns: {1,2} passes, {3,4} fails, {3} fails, {4}
	// passes -- four probes, each of one row.
	CHECK(transport->probes == 4);
	bool ordered_without_clob = false;
	for (const auto &sql : script.executed_sql) {
		if (sql.find("ORDER BY 1, 2, 4 OFFSET") != std::string::npos) {
			ordered_without_clob = true;
		}
		if (sql.find("WHERE ROWNUM <= 1") != std::string::npos) {
			CHECK(sql.find("OFFSET") == std::string::npos);
		}
	}
	CHECK(ordered_without_clob);
}

void TestStablePagingCanBeTurnedOff() {
	Script script;
	auto installed = InstallPaging(script, 1200);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto result = RunQuery(connection, "SELECT * FROM oracle_fusion_query('SELECT N FROM BIG', "
	                                   "fetch_size := 500, stable_paging := false)");

	CHECK(result->RowCount() == 1200);
	CHECK(script.executed_sql.size() == 4);
	for (const auto &sql : script.executed_sql) {
		CHECK(sql.find("ORDER BY") == std::string::npos);
	}
}

//! A scan ends on an empty page, so a report that hands back the same rows
//! whatever offset it is given would never let one end. Saying so beats
//! streaming the first page until the user gives up.
void TestARepeatedPageIsRefused() {
	struct IgnoresOffsetTransport : FusionTransport {
		std::string Execute(const std::string &, const RequestContext &) override {
			std::string rowset = "&lt;ROWSET&gt;";
			for (int i = 0; i < 10; i++) {
				rowset += "&lt;ROW&gt;&lt;N&gt;" + std::to_string(i) + "&lt;/N&gt;&lt;/ROW&gt;";
			}
			return MakeSoapResponse(MakeReportXML(rowset + "&lt;/ROWSET&gt;"));
		}
	};
	ScopedTransportFactory installed(
	    [](const FusionConfig &) { return std::make_shared<IgnoresOffsetTransport>(); });

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto result = connection.Query("SELECT * FROM oracle_fusion_query('SELECT N FROM T', fetch_size := 10)");

	CHECK(result->HasError());
	CHECK(result->GetError().find("not being paged") != std::string::npos);
	CHECK(result->GetError().find("fetch_size := 0") != std::string::npos);
}

//! Serves rows by OFFSET/FETCH like PagingTransport, but cuts every response
//! off mid-row after `rows_per_response` rows, whatever was asked for -- which
//! is what the report does when a response grows past what it will carry.
class TruncatingPagingTransport : public FusionTransport {
public:
	TruncatingPagingTransport(Script &script_p, int total_rows_p, int rows_per_response_p)
	    : script(script_p), total_rows(total_rows_p), rows_per_response(rows_per_response_p) {
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

		const int available = std::max(0, std::min(limit, total_rows - offset));
		std::string rowset = "&lt;ROWSET&gt;\n";
		for (int i = 0; i < std::min(available, rows_per_response); i++) {
			rowset += " &lt;ROW&gt;\n  &lt;N&gt;" + std::to_string(offset + i) + "&lt;/N&gt;\n &lt;/ROW&gt;\n";
		}
		if (available > rows_per_response) {
			// The cut: one more row starts and never finishes.
			rowset += " &lt;ROW&gt;\n  &lt;N&gt;" + std::to_string(offset + rows_per_response).substr(0, 1);
		} else {
			rowset += "&lt;/ROWSET&gt;";
		}
		return MakeSoapResponse(MakeReportXML(rowset));
	}

private:
	Script &script;
	int total_rows;
	int rows_per_response;
};

//! A page the report cut short is not the end and not an error: the scan
//! carries on from the rows it did receive. Otherwise an unparseable tail looks
//! like an empty page and can silently end a listing early.
void TestTruncatedPageIsContinuedFrom() {
	Script script;
	ScopedTransportFactory installed(
	    [&script](const FusionConfig &) { return std::make_shared<TruncatingPagingTransport>(script, 50, 7); });

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto result = RunQuery(connection, "SELECT * FROM oracle_fusion_query('SELECT N FROM T', fetch_size := 20)");

	CHECK(result->RowCount() == 50);
	CHECK(result->GetValue(0, 0).ToString() == "0");
	CHECK(result->GetValue(0, 49).ToString() == "49");
	// Every row exactly once: a continuation that skipped or repeated would
	// still produce fifty rows of something.
	std::set<std::string> seen;
	for (idx_t row = 0; row < result->RowCount(); row++) {
		seen.insert(result->GetValue(0, row).ToString());
	}
	CHECK(seen.size() == 50);
	// The next page starts where the cut one ended, not a page-size later.
	bool continued_from_the_cut = false;
	for (const auto &sql : script.executed_sql) {
		if (sql.find("OFFSET 7 ROWS") != std::string::npos) {
			continued_from_the_cut = true;
		}
	}
	CHECK(continued_from_the_cut);
}

//! With paging off there is nothing to continue from, and a short answer that
//! looks complete is the worst outcome, so it fails and says how much arrived.
void TestTruncatedResponseWithoutPagingIsAnError() {
	Script script;
	ScopedTransportFactory installed(
	    [&script](const FusionConfig &) { return std::make_shared<TruncatingPagingTransport>(script, 50, 7); });

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto result = connection.Query("SELECT * FROM oracle_fusion_query('SELECT N FROM T', fetch_size := 0)");

	CHECK(result->HasError());
	CHECK(result->GetError().find("cut the response off after 7 rows") != std::string::npos);
	CHECK(result->GetError().find("fetch_size := 0") != std::string::npos);
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

// ---------------------------------------------------------------------------
// Metadata and its cache
// ---------------------------------------------------------------------------

//! Answers dictionary queries by recognising which one it was asked.
class DictionaryTransport : public FusionTransport {
public:
	explicit DictionaryTransport(Script &script_p) : script(script_p) {
	}

	std::string Execute(const std::string &sql, const RequestContext &) override {
		script.executed_sql.push_back(sql);
		if (AsksForALaterPage(sql)) {
			return MakeSoapResponse(MakeReportXML("&lt;ROWSET/&gt;"));
		}

		if (sql.find("COUNT(DISTINCT") != std::string::npos) {
			// The listing asks how many rows to expect, so that a truncated
			// response is recognisable as truncated.
			return MakeSoapResponse(MakeReportXML(
			    "&lt;ROWSET&gt;&lt;ROW&gt;&lt;TABLE_COUNT&gt;2&lt;/TABLE_COUNT&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));
		}
		if (sql.find("FND_VIEWS") != std::string::npos) {
			return MakeSoapResponse(MakeReportXML(
			    "&lt;ROWSET&gt;"
			    "&lt;ROW&gt;&lt;TABLE_NAME&gt;GL_JE_HEADERS&lt;/TABLE_NAME&gt;&lt;TABLE_TYPE&gt;TABLE&lt;/TABLE_TYPE&gt;"
			    "&lt;TABLE_ID&gt;101&lt;/TABLE_ID&gt;&lt;/ROW&gt;"
			    "&lt;ROW&gt;&lt;TABLE_NAME&gt;GL_BALANCES_V&lt;/TABLE_NAME&gt;&lt;TABLE_TYPE&gt;VIEW&lt;/TABLE_TYPE&gt;"
			    "&lt;TABLE_ID&gt;102&lt;/TABLE_ID&gt;&lt;/ROW&gt;"
			    "&lt;/ROWSET&gt;"));
		}
		if (sql.find("FND_COLUMNS") != std::string::npos) {
			return MakeSoapResponse(MakeReportXML(
			    "&lt;ROWSET&gt;"
			    "&lt;ROW&gt;&lt;TABLE_NAME&gt;GL_JE_HEADERS&lt;/TABLE_NAME&gt;&lt;COLUMN_NAME&gt;JE_HEADER_ID"
			    "&lt;/COLUMN_NAME&gt;&lt;TYPE_NAME&gt;NUMBER&lt;/TYPE_NAME&gt;&lt;DECIMAL_DIGITS&gt;18"
			    "&lt;/DECIMAL_DIGITS&gt;&lt;NUM_PREC_RADIX&gt;0&lt;/NUM_PREC_RADIX&gt;&lt;ORDINAL_POSITION&gt;1"
			    "&lt;/ORDINAL_POSITION&gt;&lt;NULLABLE&gt;0&lt;/NULLABLE&gt;&lt;/ROW&gt;"
			    "&lt;ROW&gt;&lt;TABLE_NAME&gt;GL_JE_HEADERS&lt;/TABLE_NAME&gt;&lt;COLUMN_NAME&gt;NAME"
			    "&lt;/COLUMN_NAME&gt;&lt;TYPE_NAME&gt;VARCHAR2&lt;/TYPE_NAME&gt;&lt;ORDINAL_POSITION&gt;2"
			    "&lt;/ORDINAL_POSITION&gt;&lt;NULLABLE&gt;1&lt;/NULLABLE&gt;&lt;/ROW&gt;"
			    "&lt;/ROWSET&gt;"));
		}
		if (sql.find("all_tab_columns") != std::string::npos) {
			return MakeSoapResponse(MakeReportXML(
			    "&lt;ROWSET&gt;&lt;ROW&gt;&lt;TABLE_NAME&gt;GL_BALANCES_V&lt;/TABLE_NAME&gt;"
			    "&lt;COLUMN_NAME&gt;PERIOD_NAME&lt;/COLUMN_NAME&gt;&lt;TYPE_NAME&gt;VARCHAR2&lt;/TYPE_NAME&gt;"
			    "&lt;ORDINAL_POSITION&gt;1&lt;/ORDINAL_POSITION&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));
		}
		return MakeSoapResponse(MakeReportXML("&lt;ROWSET/&gt;"));
	}

private:
	Script &script;
};

ScopedTransportFactory InstallDictionary(Script &script) {
	return ScopedTransportFactory(
	    [&script](const FusionConfig &) { return std::make_shared<DictionaryTransport>(script); });
}

//! Each metadata test starts from an empty in-memory cache, so one test's
//! writes cannot make another's cache-miss assertions pass.
void ResetCache() {
	duckdb::MetadataCache::ResetForTesting("");
}

void TestListTables() {
	ResetCache();
	Script script;
	auto installed = InstallDictionary(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto result = RunQuery(connection, "SELECT table_name, table_type FROM oracle_fusion_tables() ORDER BY table_name");

	CHECK(result->RowCount() == 2);
	CHECK(result->GetValue(0, 0).ToString() == "GL_BALANCES_V");
	CHECK(result->GetValue(1, 0).ToString() == "VIEW");
	CHECK(result->GetValue(0, 1).ToString() == "GL_JE_HEADERS");

	// Four requests: the count, the rows, the empty page, and one retry of it
	// on a fresh session -- an exhausted BI Publisher session also returns
	// nothing, so an empty page is confirmed before it is believed.
	CHECK(script.executed_sql.size() == 4);
	CHECK(script.executed_sql[0].find("COUNT(DISTINCT") != std::string::npos);
	CHECK(script.executed_sql[1].find("FETCH FIRST") != std::string::npos);
	// Keyset paging, so the first page carries no seek predicate.
	CHECK(script.executed_sql[1].find("t.table_name > ") == std::string::npos);
}

//! BI Publisher truncates a response without saying so, and a truncated page
//! is indistinguishable from the last one. Treating a short page as the end
//! therefore stopped the table list partway through the alphabet -- silently,
//! so the missing tables looked like tables that do not exist.
void TestTruncatedPageDoesNotEndTheListing() {
	ResetCache();
	struct TruncatingTransport : FusionTransport {
		int pages = 0;
		std::vector<std::string> executed;

		std::string Execute(const std::string &sql, const RequestContext &) override {
			executed.push_back(sql);
			if (sql.find("COUNT(DISTINCT") != std::string::npos) {
				// Two rows exist; the pages below deliver them one at a time,
				// which is exactly the truncation this test is about.
				return MakeSoapResponse(MakeReportXML(
				    "&lt;ROWSET&gt;&lt;ROW&gt;&lt;TABLE_COUNT&gt;2&lt;/TABLE_COUNT&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));
			}
			// Three pages: two short ones the server chose to cut, then empty.
			// A page size of one row is enough to make the point.
			if (pages++ >= 2) {
				return MakeSoapResponse(MakeReportXML("&lt;ROWSET/&gt;"));
			}
			const std::string name = pages == 1 ? "AAA_FIRST" : "XLA_AE_LINES";
			return MakeSoapResponse(MakeReportXML(
			    "&lt;ROWSET&gt;&lt;ROW&gt;&lt;TABLE_NAME&gt;" + name +
			    "&lt;/TABLE_NAME&gt;&lt;TABLE_TYPE&gt;TABLE&lt;/TABLE_TYPE&gt;"
			    "&lt;TABLE_ID&gt;1&lt;/TABLE_ID&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));
		}
	};
	auto transport = std::make_shared<TruncatingTransport>();
	ScopedTransportFactory installed([&transport](const FusionConfig &) { return transport; });

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto result = RunQuery(connection, "SELECT table_name FROM oracle_fusion_tables() ORDER BY table_name");

	// Both pages, not just the first.
	CHECK(result->RowCount() == 2);
	CHECK(result->GetValue(0, 0).ToString() == "AAA_FIRST");
	CHECK(result->GetValue(0, 1).ToString() == "XLA_AE_LINES");
	// Five requests: the count, two with rows, the empty one, and its retry on
	// a fresh session.
	CHECK(transport->executed.size() == 5);
	// The cursor is the last name the page actually delivered, so a page the
	// server chose to cut short resumes from where it stopped rather than from
	// where a fixed page size would have put it.
	CHECK(transport->executed[2].find("t.table_name > 'AAA_FIRST'") != std::string::npos);
}

//! An empty page is retried on a fresh session before it is believed.
//!
//! A BI Publisher session can answer with an empty page rather than an explicit
//! failure, which is exactly what running out of data looks like. Retrying once
//! on a fresh session distinguishes that transient state from a real ending.
void TestEmptyPageIsRetriedOnAFreshSession() {
	ResetCache();
	struct ExhaustingTransport : FusionTransport {
		int pages = 0;
		int resets = 0;

		std::string Execute(const std::string &sql, const RequestContext &) override {
			if (sql.find("COUNT(DISTINCT") != std::string::npos) {
				return MakeSoapResponse(MakeReportXML(
				    "&lt;ROWSET&gt;&lt;ROW&gt;&lt;TABLE_COUNT&gt;2&lt;/TABLE_COUNT&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));
			}
			pages++;
			// The session gives one page, then goes quiet until it is reset.
			if (pages == 2 && resets == 0) {
				return MakeSoapResponse(MakeReportXML("&lt;ROWSET/&gt;"));
			}
			if (pages > 3) {
				return MakeSoapResponse(MakeReportXML("&lt;ROWSET/&gt;"));
			}
			const std::string name = pages == 1 ? "AAA_FIRST" : "ZZZ_LAST";
			return MakeSoapResponse(MakeReportXML(
			    "&lt;ROWSET&gt;&lt;ROW&gt;&lt;TABLE_NAME&gt;" + name +
			    "&lt;/TABLE_NAME&gt;&lt;TABLE_TYPE&gt;TABLE&lt;/TABLE_TYPE&gt;"
			    "&lt;TABLE_ID&gt;1&lt;/TABLE_ID&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));
		}

		void ResetSession() override {
			resets++;
		}
	};
	auto transport = std::make_shared<ExhaustingTransport>();
	ScopedTransportFactory installed([&transport](const FusionConfig &) { return transport; });

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto result = RunQuery(connection, "SELECT table_name FROM oracle_fusion_tables() ORDER BY table_name");

	// Both rows: the row after the exhausted session was not lost.
	CHECK(result->RowCount() == 2);
	CHECK(result->GetValue(0, 1).ToString() == "ZZZ_LAST");
	CHECK(transport->resets >= 1);
}

//! A listing that comes back short of what the instance says it has is
//! reported and not cached.
//!
//! This is the failure that started all of it: a truncated response produced a
//! partial dictionary, which then looked authoritative for a week, and the
//! tables it omitted appeared not to exist. Asking the instance for a count
//! first is what makes "short" detectable at all.
void TestShortListingIsReportedRatherThanCached() {
	ResetCache();
	struct ShortListingTransport : FusionTransport {
		std::string Execute(const std::string &sql, const RequestContext &) override {
			if (sql.find("COUNT(DISTINCT") != std::string::npos) {
				return MakeSoapResponse(MakeReportXML(
				    "&lt;ROWSET&gt;&lt;ROW&gt;&lt;TABLE_COUNT&gt;9000&lt;/TABLE_COUNT&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));
			}
			if (AsksForALaterPage(sql)) {
				return MakeSoapResponse(MakeReportXML("&lt;ROWSET/&gt;"));
			}
			// One row, where nine thousand were promised.
			return MakeSoapResponse(MakeReportXML(
			    "&lt;ROWSET&gt;&lt;ROW&gt;&lt;TABLE_NAME&gt;AAA_ONLY&lt;/TABLE_NAME&gt;"
			    "&lt;TABLE_TYPE&gt;TABLE&lt;/TABLE_TYPE&gt;&lt;TABLE_ID&gt;1&lt;/TABLE_ID&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));
		}
	};
	ScopedTransportFactory installed([](const FusionConfig &) { return std::make_shared<ShortListingTransport>(); });

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);

	auto result = connection.Query("SELECT * FROM oracle_fusion_tables()");
	CHECK(result->HasError());
	CHECK(result->GetError().find("9000") != std::string::npos);
	CHECK(result->GetError().find("incomplete") != std::string::npos);

	// And nothing was written, so the next attempt is not served a gap.
	auto status = RunQuery(connection, "SELECT cached_tables FROM fusion_scanner_cache_status()");
	CHECK(status->GetValue(0, 0).GetValue<int64_t>() == 0);
}

//! Without the independent count there is no proof that the last empty page is
//! the end rather than BI Publisher truncation, so the current call may use the
//! rows but they must not become a week-long cache snapshot.
void TestUnverifiedListingIsNotCached() {
	ResetCache();
	struct NoCountTransport : FusionTransport {
		int requests = 0;
		std::string Execute(const std::string &sql, const RequestContext &) override {
			requests++;
			if (sql.find("COUNT(DISTINCT") != std::string::npos) {
				throw ofquack::PermanentError("count is not available");
			}
			if (AsksForALaterPage(sql)) {
				return MakeSoapResponse(MakeReportXML("&lt;ROWSET/&gt;"));
			}
			return MakeSoapResponse(MakeReportXML(
			    "&lt;ROWSET&gt;&lt;ROW&gt;&lt;TABLE_NAME&gt;T&lt;/TABLE_NAME&gt;&lt;TABLE_TYPE&gt;TABLE&lt;/TABLE_TYPE&gt;"
			    "&lt;TABLE_ID&gt;1&lt;/TABLE_ID&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));
		}
	};
	auto transport = std::make_shared<NoCountTransport>();
	ScopedTransportFactory installed([transport](const FusionConfig &) { return transport; });

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto first = RunQuery(connection, "SELECT table_name FROM oracle_fusion_tables()");
	CHECK(first->RowCount() == 1);
	auto status = RunQuery(connection, "SELECT cached_tables FROM fusion_scanner_cache_status()");
	CHECK(status->GetValue(0, 0).GetValue<int64_t>() == 0);
	const auto after_first = transport->requests;
	RunQuery(connection, "SELECT table_name FROM oracle_fusion_tables()");
	CHECK(transport->requests > after_first);
}

//! The whole reason the cache exists: every metadata question costs a BI
//! Publisher call measured in seconds.
void TestSecondListingCostsNothing() {
	ResetCache();
	Script script;
	auto installed = InstallDictionary(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	RunQuery(connection, "SELECT * FROM oracle_fusion_tables()");
	const auto after_first = script.executed_sql.size();

	// A separate connection, to prove the cache is not per-connection state.
	Connection second(db);
	CreateSecret(second, "fusion2");
	auto result = RunQuery(second, "SELECT * FROM oracle_fusion_tables(secret := 'fusion')");

	CHECK(result->RowCount() == 2);
	CHECK(script.executed_sql.size() == after_first);
}

//! "This object has no columns we can read" is an answer, and it cost a request
//! to obtain. Left unrecorded it is indistinguishable from never having asked,
//! so every connection asks again -- for exactly the objects Fusion refuses to
//! describe, which are the ones people look at twice.
void TestAnEmptyColumnListIsCached() {
	ResetCache();
	Script script;
	struct NoColumnsTransport : FusionTransport {
		Script &script;
		explicit NoColumnsTransport(Script &script_p) : script(script_p) {
		}
		std::string Execute(const std::string &sql, const RequestContext &) override {
			script.executed_sql.push_back(sql);
			if (AsksForALaterPage(sql)) {
				return MakeSoapResponse(MakeReportXML("&lt;ROWSET/&gt;"));
			}
			if (sql.find("COUNT(DISTINCT") != std::string::npos) {
				return MakeSoapResponse(MakeReportXML("&lt;ROWSET&gt;&lt;ROW&gt;&lt;TABLE_COUNT&gt;1"
				                                      "&lt;/TABLE_COUNT&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));
			}
			if (sql.find("FND_VIEWS") != std::string::npos) {
				return MakeSoapResponse(
				    MakeReportXML("&lt;ROWSET&gt;&lt;ROW&gt;&lt;TABLE_NAME&gt;SECRET_T&lt;/TABLE_NAME&gt;"
				                  "&lt;TABLE_TYPE&gt;TABLE&lt;/TABLE_TYPE&gt;&lt;TABLE_ID&gt;7&lt;/TABLE_ID&gt;"
				                  "&lt;/ROW&gt;&lt;/ROWSET&gt;"));
			}
			// The column query answers with nothing at all.
			return MakeSoapResponse(MakeReportXML("&lt;ROWSET/&gt;"));
		}
	};
	ScopedTransportFactory installed(
	    [&script](const FusionConfig &) { return std::make_shared<NoColumnsTransport>(script); });

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto first = RunQuery(connection, "SELECT * FROM oracle_fusion_columns('SECRET_T')");
	CHECK(first->RowCount() == 0);
	const auto after_first = script.executed_sql.size();

	auto second = RunQuery(connection, "SELECT * FROM oracle_fusion_columns('SECRET_T')");
	CHECK(second->RowCount() == 0);
	CHECK(script.executed_sql.size() == after_first);
}

void TestRefreshBypassesTheCache() {
	ResetCache();
	Script script;
	auto installed = InstallDictionary(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	RunQuery(connection, "SELECT * FROM oracle_fusion_tables()");
	const auto after_first = script.executed_sql.size();

	RunQuery(connection, "SELECT * FROM oracle_fusion_tables(refresh := true)");
	CHECK(script.executed_sql.size() > after_first);
}

void TestInvalidateForcesARefetch() {
	ResetCache();
	Script script;
	auto installed = InstallDictionary(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	RunQuery(connection, "SELECT * FROM oracle_fusion_tables()");
	const auto after_first = script.executed_sql.size();

	auto removed = RunQuery(connection, "SELECT tables_removed FROM fusion_scanner_cache_invalidate()");
	CHECK(removed->GetValue(0, 0).GetValue<int64_t>() == 2);

	RunQuery(connection, "SELECT * FROM oracle_fusion_tables()");
	CHECK(script.executed_sql.size() > after_first);
}

//! A table-list snapshot and the count that validates it are one cache unit.
//! Invalidating the list must not leave an old count attached to the next one.
void TestInvalidateRemovesExpectedCountAndOrderKeys() {
	ResetCache();
	auto &cache = duckdb::MetadataCache::Get();
	const std::string scope = "scope";
	cache.PutTables(scope, {ofquack::TableInfo {"T", "TABLE", "", "1"}}, 1);
	CHECK(cache.ExpectedTables(scope) == 1);

	cache.PutOrderKey(scope, "T", {"ID"});
	std::vector<std::string> key;
	CHECK(cache.TryGetOrderKey(scope, "T", 3600, key));
	CHECK(key.size() == 1 && key[0] == "ID");

	cache.InvalidateColumns(scope, "T");
	key.clear();
	CHECK(!cache.TryGetOrderKey(scope, "T", 3600, key));

	cache.InvalidateTables(scope);
	CHECK(cache.ExpectedTables(scope) == -1);
	cache.PutTables(scope, {ofquack::TableInfo {"T", "TABLE", "", "1"}}, -1);
	CHECK(cache.ExpectedTables(scope) == -1);
}

//! Metadata visibility can differ by account, so users of one Fusion instance
//! must not share a dictionary cache merely because the endpoint is the same.
void TestCacheIsKeyedByPrincipal() {
	FusionConfig first;
	first.endpoint = "https://fusion.example.com/service";
	first.report_path = "/Custom/RP_ARB.xdo";
	first.username = "alice";
	FusionConfig second = first;
	second.username = "bob";
	CHECK(duckdb::EndpointKey(first, ofquack::metadata::DICTIONARY_SCHEMA) !=
	      duckdb::EndpointKey(second, ofquack::metadata::DICTIONARY_SCHEMA));
	// The schema decides which objects the dictionary queries can see, so the
	// same instance under two owners is two catalogues, not one.
	CHECK(duckdb::EndpointKey(first, "FUSION") != duckdb::EndpointKey(first, "CUSTOM"));
}

//! An empty report carries no column names at all, so a result that matched
//! nothing had no schema and could only be an error. A declared schema is the
//! way out, and the way to pin a type a twenty-row sample gets wrong.
void TestDeclaredColumns() {
	Script script;
	script.response = MakeSoapResponse(MakeReportXML("&lt;ROWSET/&gt;"));
	auto installed = InstallFake(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);

	// Without it, no rows means no schema.
	auto no_schema = connection.Query("SELECT * FROM oracle_fusion_query('SELECT ID FROM T WHERE 1=0')");
	CHECK(no_schema->HasError());
	CHECK(no_schema->GetError().find("columns :=") != std::string::npos);

	auto declared = RunQuery(connection, "SELECT * FROM oracle_fusion_query('SELECT ID FROM T WHERE 1=0', "
	                                     "columns := {'ID': 'BIGINT', 'NAME': 'VARCHAR'})");
	CHECK(declared->RowCount() == 0);
	CHECK(declared->ColumnCount() == 2);
	CHECK(declared->names[0] == "ID");
	CHECK(declared->types[0] == duckdb::LogicalType::BIGINT);
	CHECK(declared->names[1] == "NAME");
	CHECK(declared->types[1] == duckdb::LogicalType::VARCHAR);

	// It wins over what the data would have said, always: a column of digits
	// that is really an identifier stays text because the caller said so.
	Script with_rows;
	with_rows.response = MakeSoapResponse(
	    MakeReportXML("&lt;ROWSET&gt;&lt;ROW&gt;&lt;ID&gt;42&lt;/ID&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));
	auto reinstalled = InstallFake(with_rows);
	auto overridden = RunQuery(connection, "SELECT * FROM oracle_fusion_query('SELECT ID FROM T', fetch_size := 0, "
	                                       "columns := {'ID': 'VARCHAR'})");
	CHECK(overridden->types[0] == duckdb::LogicalType::VARCHAR);
	CHECK(overridden->GetValue(0, 0).ToString() == "42");

	// A name the report did not return would be a column of nothing but NULLs,
	// which is indistinguishable from a column of NULL data. Refused while there
	// is a page to check against.
	auto misspelt = connection.Query("SELECT * FROM oracle_fusion_query('SELECT ID FROM T', fetch_size := 0, "
	                                 "columns := {'IDD': 'BIGINT'})");
	CHECK(misspelt->HasError());
	CHECK(misspelt->GetError().find("IDD") != std::string::npos);
	CHECK(misspelt->GetError().find("It returned: ID") != std::string::npos);
}

//! A type is a guess about the rest of the data, from a sample of the first
//! page or from a dictionary the data can contradict. Reading the odd value
//! that does not fit as NULL keeps the other million rows, and loses the fact
//! that anything was wrong; which of the two costs more is the caller's to say.
void TestCastErrorModeInQueryFunction() {
	Script script;
	// Twenty integers is the whole type sample, so the column infers as a
	// number; the value after it does not fit and is never seen by inference.
	std::string rows;
	for (int i = 0; i < 20; i++) {
		rows += "&lt;ROW&gt;&lt;N&gt;" + std::to_string(i + 1) + "&lt;/N&gt;&lt;/ROW&gt;";
	}
	rows += "&lt;ROW&gt;&lt;N&gt;not a number&lt;/N&gt;&lt;/ROW&gt;";
	script.response = MakeSoapResponse(MakeReportXML("&lt;ROWSET&gt;" + rows + "&lt;/ROWSET&gt;"));
	auto installed = InstallFake(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);

	auto nullified = RunQuery(connection, "SELECT count(*) AS rows, count(N) AS present FROM "
	                                      "oracle_fusion_query('SELECT N FROM T', fetch_size := 0)");
	CHECK(nullified->GetValue(0, 0).GetValue<int64_t>() == 21);
	CHECK(nullified->GetValue(1, 0).GetValue<int64_t>() == 20);

	auto failed = connection.Query("SELECT * FROM oracle_fusion_query('SELECT N FROM T', fetch_size := 0, "
	                               "on_cast_error := 'error')");
	CHECK(failed->HasError());
	// The value is named: finding it otherwise costs another full scan.
	CHECK(failed->GetError().find("not a number") != std::string::npos);
	CHECK(failed->GetError().find("\"N\"") != std::string::npos);
	CHECK(failed->GetError().find("on_cast_error := 'null'") != std::string::npos);
}

//! The same choice has to reach the attached catalog, where the type comes from
//! the dictionary rather than a sample. A setting that silently does not apply
//! to half the extension is worse than no setting.
void TestCastErrorModeInAttachedCatalog() {
	ResetCache();
	struct MismatchTransport : FusionTransport {
		std::string Execute(const std::string &sql, const RequestContext &) override {
			if (sql.find("COUNT(DISTINCT") != std::string::npos) {
				return MakeSoapResponse(MakeReportXML(
				    "&lt;ROWSET&gt;&lt;ROW&gt;&lt;TABLE_COUNT&gt;1&lt;/TABLE_COUNT&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));
			}
			if (sql.find("FND_COLUMNS") != std::string::npos) {
				return MakeSoapResponse(MakeReportXML(
				    "&lt;ROWSET&gt;&lt;ROW&gt;&lt;TABLE_NAME&gt;T&lt;/TABLE_NAME&gt;&lt;COLUMN_NAME&gt;N"
				    "&lt;/COLUMN_NAME&gt;&lt;TYPE_NAME&gt;NUMBER&lt;/TYPE_NAME&gt;&lt;DECIMAL_DIGITS&gt;18"
				    "&lt;/DECIMAL_DIGITS&gt;&lt;ORDINAL_POSITION&gt;1&lt;/ORDINAL_POSITION&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));
			}
			if (sql.find("FND_VIEWS") != std::string::npos) {
				// The listing seeks, so a page asking for names after the last
				// one has to come back empty or the fetcher refuses a listing
				// that never advances.
				if (sql.find("t.table_name >") != std::string::npos) {
					return MakeSoapResponse(MakeReportXML("&lt;ROWSET/&gt;"));
				}
				return MakeSoapResponse(MakeReportXML(
				    "&lt;ROWSET&gt;&lt;ROW&gt;&lt;TABLE_NAME&gt;T&lt;/TABLE_NAME&gt;&lt;TABLE_TYPE&gt;TABLE"
				    "&lt;/TABLE_TYPE&gt;&lt;TABLE_ID&gt;1&lt;/TABLE_ID&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));
			}
			if (AsksForALaterPage(sql)) {
				return MakeSoapResponse(MakeReportXML("&lt;ROWSET/&gt;"));
			}
			// The dictionary says NUMBER(18,0); the data disagrees.
			return MakeSoapResponse(
			    MakeReportXML("&lt;ROWSET&gt;&lt;ROW&gt;&lt;N&gt;not a number&lt;/N&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));
		}
	};
	auto transport = std::make_shared<MismatchTransport>();
	ScopedTransportFactory installed([transport](const FusionConfig &) { return transport; });

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	RunQuery(connection, "ATTACH 'fusion' AS f (TYPE oracle_fusion, FETCH_SIZE 0)");
	auto nullified = RunQuery(connection, "SELECT N FROM f.main.T");
	CHECK(nullified->RowCount() == 1);
	CHECK(nullified->GetValue(0, 0).IsNull());

	RunQuery(connection, "DETACH f");
	RunQuery(connection, "ATTACH 'fusion' AS g (TYPE oracle_fusion, FETCH_SIZE 0, ON_CAST_ERROR 'error')");
	auto failed = connection.Query("SELECT N FROM g.main.T");
	CHECK(failed->HasError());
	CHECK(failed->GetError().find("not a number") != std::string::npos);
	CHECK(failed->GetError().find("\"N\"") != std::string::npos);
}

//! SCHEMA was accepted by CREATE SECRET and read by nothing: the owner the
//! dictionary queries filter on was a compile-time constant, so a deployment
//! that did not use FUSION had no way to say so and got an empty catalogue.
void TestSecretSchemaReachesTheDictionaryQueries() {
	ResetCache();
	Script script;
	struct RecordingTransport : FusionTransport {
		Script &script;
		explicit RecordingTransport(Script &script_p) : script(script_p) {
		}
		std::string Execute(const std::string &sql, const RequestContext &) override {
			script.executed_sql.push_back(sql);
			if (sql.find("COUNT(DISTINCT") != std::string::npos) {
				return MakeSoapResponse(MakeReportXML(
				    "&lt;ROWSET&gt;&lt;ROW&gt;&lt;TABLE_COUNT&gt;1&lt;/TABLE_COUNT&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));
			}
			if (AsksForALaterPage(sql)) {
				return MakeSoapResponse(MakeReportXML("&lt;ROWSET/&gt;"));
			}
			return MakeSoapResponse(MakeReportXML(
			    "&lt;ROWSET&gt;&lt;ROW&gt;&lt;TABLE_NAME&gt;SOME_V&lt;/TABLE_NAME&gt;"
			    "&lt;TABLE_TYPE&gt;VIEW&lt;/TABLE_TYPE&gt;&lt;TABLE_ID&gt;&lt;/TABLE_ID&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));
		}
	};
	ScopedTransportFactory installed(
	    [&script](const FusionConfig &) { return std::make_shared<RecordingTransport>(script); });

	DuckDB db(nullptr);
	Connection connection(db);
	RunQuery(connection, "CREATE OR REPLACE SECRET fusion (TYPE oracle_fusion, ENDPOINT 'https://fusion.example.com', "
	                     "REPORT_PATH '/Custom/RP_ARB.xdo', USERNAME 'u', PASSWORD 'p', SCHEMA 'custom_owner')");
	RunQuery(connection, "SELECT * FROM oracle_fusion_columns('SOME_V')");

	bool asked_custom_owner = false;
	bool asked_fusion = false;
	for (const auto &sql : script.executed_sql) {
		asked_custom_owner = asked_custom_owner || sql.find("owner = 'CUSTOM_OWNER'") != std::string::npos;
		asked_fusion = asked_fusion || sql.find("owner = 'FUSION'") != std::string::npos;
	}
	CHECK(asked_custom_owner);
	CHECK(!asked_fusion);
}

//! Unknown completeness is not complete. The status must also distinguish
//! rows on disk from fresh rows and report how many tables have descriptions.
void TestCacheStatusDoesNotCallUnknownComplete() {
	ResetCache();
	Script script;
	auto installed = InstallDictionary(script);
	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto status = RunQuery(
	    connection, "SELECT complete, fresh_tables, fresh_columns, described_tables FROM fusion_scanner_cache_status()");
	CHECK(status->GetValue(0, 0).IsNull());
	CHECK(status->GetValue(1, 0).GetValue<int64_t>() == 0);
	CHECK(status->GetValue(2, 0).GetValue<int64_t>() == 0);
	CHECK(status->GetValue(3, 0).GetValue<int64_t>() == 0);
}

//! Columns of a table come from FND_COLUMNS by TABLE_ID; columns of a view are
//! not there at all and come from ALL_TAB_COLUMNS.
void TestColumnsOfTableAndView() {
	ResetCache();
	Script script;
	auto installed = InstallDictionary(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);

	auto table_columns =
	    RunQuery(connection, "SELECT column_name, oracle_type, duckdb_type FROM oracle_fusion_columns('GL_JE_HEADERS')");
	CHECK(table_columns->RowCount() == 2);
	CHECK(table_columns->GetValue(0, 0).ToString() == "JE_HEADER_ID");
	// NUMBER(18,0) from the dictionary maps to BIGINT. Note the source aliases
	// are shifted: DECIMAL_DIGITS carried the precision.
	CHECK(table_columns->GetValue(2, 0).ToString() == "BIGINT");
	CHECK(table_columns->GetValue(2, 1).ToString() == "VARCHAR");

	bool asked_fnd_columns = false;
	for (const auto &sql : script.executed_sql) {
		asked_fnd_columns = asked_fnd_columns || sql.find("FND_COLUMNS") != std::string::npos;
	}
	CHECK(asked_fnd_columns);

	auto view_columns = RunQuery(connection, "SELECT column_name FROM oracle_fusion_columns('GL_BALANCES_V')");
	CHECK(view_columns->RowCount() == 1);
	CHECK(view_columns->GetValue(0, 0).ToString() == "PERIOD_NAME");

	bool asked_all_tab_columns = false;
	for (const auto &sql : script.executed_sql) {
		asked_all_tab_columns = asked_all_tab_columns || sql.find("all_tab_columns") != std::string::npos;
	}
	CHECK(asked_all_tab_columns);
}

//! A complete short metadata page proves that there is no next page. It must
//! not pay for an empty probe (and then repeat that probe after ResetSession).
void TestMetadataShortPageEndsImmediately() {
	struct ShortPageTransport : FusionTransport {
		int requests = 0;
		int resets = 0;

		std::string Execute(const std::string &, const RequestContext &) override {
			requests++;
			return MakeSoapResponse(MakeReportXML(
			    "&lt;ROWSET&gt;&lt;ROW&gt;&lt;TABLE_NAME&gt;T&lt;/TABLE_NAME&gt;"
			    "&lt;COLUMN_NAME&gt;C1&lt;/COLUMN_NAME&gt;&lt;TYPE_NAME&gt;VARCHAR2&lt;/TYPE_NAME&gt;"
			    "&lt;ORDINAL_POSITION&gt;1&lt;/ORDINAL_POSITION&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));
		}

		void ResetSession() override {
			resets++;
		}
	};
	ShortPageTransport transport;
	ofquack::TableInfo table;
	table.name = "T";
	table.type = "TABLE";
	table.table_id = "1";

	const auto columns = ofquack::FetchColumnsOfTables(transport, RequestContext::None(), ofquack::metadata::DICTIONARY_SCHEMA, {table});
	CHECK(columns.size() == 1);
	CHECK(transport.requests == 1);
	CHECK(transport.resets == 0);
}

//! The SQL limit and the full-page threshold must be the same constant. If one
//! followed the table-list default while the other stayed at the column limit,
//! this would either stop after the first full page or ask for 2,000 wide rows.
void TestMetadataColumnPageSizeControlsQueryAndCompletion() {
	struct FullPageTransport : FusionTransport {
		int requests = 0;
		int resets = 0;
		bool used_column_page_size = false;

		std::string Execute(const std::string &sql, const RequestContext &) override {
			requests++;
			used_column_page_size =
			    used_column_page_size ||
			    sql.find("FETCH NEXT " + std::to_string(ofquack::metadata::COLUMN_PAGE_SIZE) + " ROWS ONLY") !=
			        std::string::npos;
			if (AsksForALaterPage(sql)) {
				return MakeSoapResponse(MakeReportXML("&lt;ROWSET/&gt;"));
			}
			std::string rows = "&lt;ROWSET&gt;";
			for (size_t i = 0; i < ofquack::metadata::COLUMN_PAGE_SIZE; i++) {
				rows += "&lt;ROW&gt;&lt;TABLE_NAME&gt;T&lt;/TABLE_NAME&gt;&lt;COLUMN_NAME&gt;C" +
				        std::to_string(i) +
				        "&lt;/COLUMN_NAME&gt;&lt;TYPE_NAME&gt;VARCHAR2&lt;/TYPE_NAME&gt;&lt;ORDINAL_POSITION&gt;" +
				        std::to_string(i + 1) + "&lt;/ORDINAL_POSITION&gt;&lt;/ROW&gt;";
			}
			return MakeSoapResponse(MakeReportXML(rows + "&lt;/ROWSET&gt;"));
		}

		void ResetSession() override {
			resets++;
		}
	};
	FullPageTransport transport;
	ofquack::TableInfo table;
	table.name = "T";
	table.type = "TABLE";
	table.table_id = "1";

	const auto columns = ofquack::FetchColumnsOfTables(transport, RequestContext::None(), ofquack::metadata::DICTIONARY_SCHEMA, {table});
	CHECK(columns.size() == ofquack::metadata::COLUMN_PAGE_SIZE);
	CHECK(transport.requests == 2);
	CHECK(transport.resets == 0);
	CHECK(transport.used_column_page_size);
}

//! A short page is not the end when ParseRows saw that BI Publisher cut the
//! XML. Continue from the one complete row that did arrive.
void TestMetadataTruncatedShortPageContinues() {
	struct TruncatedPageTransport : FusionTransport {
		int requests = 0;

		std::string Execute(const std::string &sql, const RequestContext &) override {
			requests++;
			if (AsksForALaterPage(sql)) {
				return MakeSoapResponse(MakeReportXML(
				    "&lt;ROWSET&gt;&lt;ROW&gt;&lt;TABLE_NAME&gt;T&lt;/TABLE_NAME&gt;"
				    "&lt;COLUMN_NAME&gt;C2&lt;/COLUMN_NAME&gt;&lt;TYPE_NAME&gt;VARCHAR2&lt;/TYPE_NAME&gt;"
				    "&lt;ORDINAL_POSITION&gt;2&lt;/ORDINAL_POSITION&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));
			}
			return MakeSoapResponse(MakeReportXML(
			    "&lt;ROWSET&gt;&lt;ROW&gt;&lt;TABLE_NAME&gt;T&lt;/TABLE_NAME&gt;"
			    "&lt;COLUMN_NAME&gt;C1&lt;/COLUMN_NAME&gt;&lt;TYPE_NAME&gt;VARCHAR2&lt;/TYPE_NAME&gt;"
			    "&lt;ORDINAL_POSITION&gt;1&lt;/ORDINAL_POSITION&gt;&lt;/ROW&gt;"
			    "&lt;ROW&gt;&lt;TABLE_NAME&gt;T&lt;/TABLE_NAME&gt;&lt;COLUMN_NAME&gt;cut"));
		}
	};
	TruncatedPageTransport transport;
	ofquack::TableInfo table;
	table.name = "T";
	table.type = "TABLE";
	table.table_id = "1";

	const auto columns = ofquack::FetchColumnsOfTables(transport, RequestContext::None(), ofquack::metadata::DICTIONARY_SCHEMA, {table});
	CHECK(columns.size() == 2);
	CHECK(columns[0].name == "C1");
	CHECK(columns[1].name == "C2");
	CHECK(transport.requests == 2);
}

//! Fusion declares its amount columns as a bare NUMBER, with neither precision
//! nor scale. DECIMAL needs a scale and the only one on offer was zero, so
//! GL_JE_LINES.ENTERED_DR -- and every amount beside it -- was read as a whole
//! number: Oracle writes 0.84 as ".84", and DECIMAL(38,0) rounded it to 1.
void TestUnconstrainedNumberIsDouble() {
	ResetCache();
	struct AmountsTransport : FusionTransport {
		std::string Execute(const std::string &sql, const RequestContext &) override {
			if (sql.find("COUNT(DISTINCT") != std::string::npos) {
				return MakeSoapResponse(MakeReportXML(
				    "&lt;ROWSET&gt;&lt;ROW&gt;&lt;TABLE_COUNT&gt;1&lt;/TABLE_COUNT&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));
			}
			if (AsksForALaterPage(sql)) {
				return MakeSoapResponse(MakeReportXML("&lt;ROWSET/&gt;"));
			}
			if (sql.find("FND_COLUMNS") != std::string::npos) {
				// No DECIMAL_DIGITS and no NUM_PREC_RADIX: nothing was declared.
				return MakeSoapResponse(MakeReportXML(
				    "&lt;ROWSET&gt;"
				    "&lt;ROW&gt;&lt;TABLE_NAME&gt;AMOUNTS&lt;/TABLE_NAME&gt;&lt;COLUMN_NAME&gt;ENTERED_DR"
				    "&lt;/COLUMN_NAME&gt;&lt;TYPE_NAME&gt;NUMBER&lt;/TYPE_NAME&gt;"
				    "&lt;ORDINAL_POSITION&gt;1&lt;/ORDINAL_POSITION&gt;&lt;/ROW&gt;"
				    "&lt;ROW&gt;&lt;TABLE_NAME&gt;AMOUNTS&lt;/TABLE_NAME&gt;&lt;COLUMN_NAME&gt;LINE_ID"
				    "&lt;/COLUMN_NAME&gt;&lt;TYPE_NAME&gt;NUMBER&lt;/TYPE_NAME&gt;&lt;DECIMAL_DIGITS&gt;18"
				    "&lt;/DECIMAL_DIGITS&gt;&lt;ORDINAL_POSITION&gt;2&lt;/ORDINAL_POSITION&gt;&lt;/ROW&gt;"
				    "&lt;/ROWSET&gt;"));
			}
			return MakeSoapResponse(MakeReportXML(
			    "&lt;ROWSET&gt;&lt;ROW&gt;&lt;TABLE_NAME&gt;AMOUNTS&lt;/TABLE_NAME&gt;"
			    "&lt;TABLE_TYPE&gt;TABLE&lt;/TABLE_TYPE&gt;&lt;TABLE_ID&gt;1&lt;/TABLE_ID&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));
		}
	};
	auto transport = std::make_shared<AmountsTransport>();
	ScopedTransportFactory installed([transport](const FusionConfig &) { return transport; });

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto columns =
	    RunQuery(connection, "SELECT column_name, duckdb_type FROM oracle_fusion_columns('AMOUNTS') ORDER BY 1");
	CHECK(columns->RowCount() == 2);
	CHECK(columns->GetValue(0, 0).ToString() == "ENTERED_DR");
	CHECK(columns->GetValue(1, 0).ToString() == "DOUBLE");
	// A declared precision still means an exact type, and an identifier that
	// fits BIGINT must not become a float.
	CHECK(columns->GetValue(0, 1).ToString() == "LINE_ID");
	CHECK(columns->GetValue(1, 1).ToString() == "BIGINT");

	// The choice is the caller's, and it reaches both the metadata function and
	// the catalog that builds a table's schema from the same mapping.
	auto as_decimal = RunQuery(connection, "SELECT duckdb_type, lossy FROM oracle_fusion_columns('AMOUNTS', "
	                                       "number_mode := 'decimal') ORDER BY column_name");
	CHECK(as_decimal->GetValue(0, 0).ToString() == "DECIMAL(38,6)");
	CHECK(as_decimal->GetValue(1, 0).GetValue<bool>());
	// A declared precision is a fact rather than a choice, so nothing is lost.
	CHECK(as_decimal->GetValue(0, 1).ToString() == "BIGINT");
	CHECK(!as_decimal->GetValue(1, 1).GetValue<bool>());

	auto as_text = RunQuery(connection, "SELECT duckdb_type, lossy FROM oracle_fusion_columns('AMOUNTS', "
	                                    "number_mode := 'text') ORDER BY column_name");
	CHECK(as_text->GetValue(0, 0).ToString() == "VARCHAR");
	CHECK(!as_text->GetValue(1, 0).GetValue<bool>());

	RunQuery(connection, "ATTACH 'fusion' AS f (TYPE oracle_fusion, NUMBER_MODE 'decimal')");
	auto attached = RunQuery(connection, "SELECT data_type FROM duckdb_columns() WHERE table_name = 'AMOUNTS' "
	                                     "AND column_name = 'ENTERED_DR'");
	CHECK(attached->RowCount() == 1);
	CHECK(attached->GetValue(0, 0).ToString() == "DECIMAL(38,6)");

	auto rejected = connection.Query("SELECT * FROM oracle_fusion_columns('AMOUNTS', number_mode := 'float')");
	CHECK(rejected->HasError());
	CHECK(rejected->GetError().find("number_mode must be") != std::string::npos);
}

void TestUnknownTableIsReported() {
	ResetCache();
	Script script;
	auto installed = InstallDictionary(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto result = connection.Query("SELECT * FROM oracle_fusion_columns('NO_SUCH_TABLE')");

	CHECK(result->HasError());
	CHECK(result->GetError().find("NO_SUCH_TABLE") != std::string::npos);
}

void TestCacheStatusReportsMode() {
	ResetCache();
	Script script;
	auto installed = InstallDictionary(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	RunQuery(connection, "SELECT * FROM oracle_fusion_tables()");

	auto status = RunQuery(connection, "SELECT mode, cached_tables FROM fusion_scanner_cache_status()");
	CHECK(status->RowCount() == 1);
	// ResetForTesting("") opens the cache in memory.
	CHECK(status->GetValue(0, 0).ToString() == "memory");
	CHECK(status->GetValue(1, 0).GetValue<int64_t>() == 2);
}

//! Population locks live only while callers may still acquire or hold them.
//! Keeping one strong owner in the map retained a mutex and its 29k possible
//! resource keys until process exit after a full dictionary warm.
void TestPopulationMutexIsReleasedAfterItsUsers() {
	auto &cache = duckdb::MetadataCache::Get();
	std::weak_ptr<std::mutex> observer;
	{
		auto first = cache.PopulationMutex("test:population-lifetime");
		observer = first;
		auto second = cache.PopulationMutex("test:population-lifetime");
		CHECK(first == second);
		first.reset();
		auto while_still_owned = cache.PopulationMutex("test:population-lifetime");
		CHECK(second == while_still_owned);
	}
	CHECK(observer.expired());

	auto next_generation = cache.PopulationMutex("test:population-lifetime");
	CHECK(next_generation != nullptr);
}

//! Two instances must not share cached metadata: a table that exists on
//! development need not exist on production.
void TestCacheIsKeyedByEndpoint() {
	ResetCache();
	Script script;
	auto installed = InstallDictionary(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	RunQuery(connection, "SELECT * FROM oracle_fusion_tables()");
	const auto after_first = script.executed_sql.size();

	// Same report, different host.
	RunQuery(connection, "SELECT * FROM oracle_fusion_tables(endpoint := 'https://other.example.com/x?WSDL')");
	CHECK(script.executed_sql.size() > after_first);
}

//! Querying the base HR table returns rows the caller may not be entitled to
//! see; the secured view applies Fusion's row-level security.
void TestSecuredViewsRewriteIsApplied() {
	Script script;
	script.response = MakeSoapResponse(
	    MakeReportXML("&lt;ROWSET&gt;&lt;ROW&gt;&lt;N&gt;1&lt;/N&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));
	auto installed = InstallFake(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	RunQuery(connection, "SELECT * FROM oracle_fusion_query('SELECT N FROM PER_ALL_PEOPLE_F', "
	                     "secured_views := true, fetch_size := 0)");

	CHECK(script.executed_sql.size() == 1);
	CHECK(script.executed_sql[0].find("PER_PERSON_SECURED_LIST_V") != std::string::npos);
	CHECK(script.executed_sql[0].find("PER_ALL_PEOPLE_F") == std::string::npos);
}

void TestSecuredViewsIsOffByDefault() {
	Script script;
	script.response = MakeSoapResponse(
	    MakeReportXML("&lt;ROWSET&gt;&lt;ROW&gt;&lt;N&gt;1&lt;/N&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));
	auto installed = InstallFake(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	RunQuery(connection, "SELECT * FROM oracle_fusion_query('SELECT N FROM PER_ALL_PEOPLE_F', fetch_size := 0)");

	CHECK(script.executed_sql[0].find("PER_ALL_PEOPLE_F") != std::string::npos);
}

// ---------------------------------------------------------------------------
// ATTACH
// ---------------------------------------------------------------------------

//! Serves the dictionary and then rows for GL_JE_HEADERS, recording the
//! statements so a test can assert what was actually sent.
class CatalogTransport : public FusionTransport {
public:
	explicit CatalogTransport(Script &script_p) : script(script_p) {
	}

	std::string Execute(const std::string &sql, const RequestContext &) override {
		script.executed_sql.push_back(sql);
		if (AsksForALaterPage(sql)) {
			return MakeSoapResponse(MakeReportXML("&lt;ROWSET/&gt;"));
		}

		if (sql.find("COUNT(DISTINCT") != std::string::npos) {
			return MakeSoapResponse(MakeReportXML(
			    "&lt;ROWSET&gt;&lt;ROW&gt;&lt;TABLE_COUNT&gt;1&lt;/TABLE_COUNT&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));
		}
		if (sql.find("FND_VIEWS") != std::string::npos) {
			return MakeSoapResponse(MakeReportXML(
			    "&lt;ROWSET&gt;&lt;ROW&gt;&lt;TABLE_NAME&gt;GL_JE_HEADERS&lt;/TABLE_NAME&gt;"
			    "&lt;TABLE_TYPE&gt;TABLE&lt;/TABLE_TYPE&gt;&lt;TABLE_ID&gt;101&lt;/TABLE_ID&gt;&lt;/ROW&gt;"
			    "&lt;/ROWSET&gt;"));
		}
		if (sql.find("FND_COLUMNS") != std::string::npos) {
			return MakeSoapResponse(MakeReportXML(
			    "&lt;ROWSET&gt;"
			    "&lt;ROW&gt;&lt;TABLE_NAME&gt;GL_JE_HEADERS&lt;/TABLE_NAME&gt;&lt;COLUMN_NAME&gt;JE_HEADER_ID"
			    "&lt;/COLUMN_NAME&gt;&lt;TYPE_NAME&gt;NUMBER&lt;/TYPE_NAME&gt;&lt;DECIMAL_DIGITS&gt;9"
			    "&lt;/DECIMAL_DIGITS&gt;&lt;NUM_PREC_RADIX&gt;0&lt;/NUM_PREC_RADIX&gt;&lt;ORDINAL_POSITION&gt;1"
			    "&lt;/ORDINAL_POSITION&gt;&lt;/ROW&gt;"
			    "&lt;ROW&gt;&lt;TABLE_NAME&gt;GL_JE_HEADERS&lt;/TABLE_NAME&gt;&lt;COLUMN_NAME&gt;NAME"
			    "&lt;/COLUMN_NAME&gt;&lt;TYPE_NAME&gt;VARCHAR2&lt;/TYPE_NAME&gt;&lt;ORDINAL_POSITION&gt;2"
			    "&lt;/ORDINAL_POSITION&gt;&lt;/ROW&gt;"
			    "&lt;/ROWSET&gt;"));
		}
		if (sql.find("all_indexes") != std::string::npos) {
			return MakeSoapResponse(MakeReportXML("&lt;ROWSET/&gt;"));
		}
		if (sql.find("\"JE_HEADER_ID\" > 2") != std::string::npos) {
			// A seek past the last row there is: the page after the data.
			return MakeSoapResponse(MakeReportXML("&lt;ROWSET/&gt;"));
		}
		if (sql.find("all_constraints") != std::string::npos) {
			// The primary key, which is what a paged scan seeks by.
			return MakeSoapResponse(MakeReportXML(
			    "&lt;ROWSET&gt;&lt;ROW&gt;&lt;COLUMN_NAME&gt;JE_HEADER_ID&lt;/COLUMN_NAME&gt;"
			    "&lt;KEY_SEQ&gt;1&lt;/KEY_SEQ&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));
		}
		// A scan of the table itself.
		return MakeSoapResponse(MakeReportXML(
		    "&lt;ROWSET&gt;"
		    "&lt;ROW&gt;&lt;JE_HEADER_ID&gt;1&lt;/JE_HEADER_ID&gt;&lt;NAME&gt;Alpha&lt;/NAME&gt;&lt;/ROW&gt;"
		    "&lt;ROW&gt;&lt;JE_HEADER_ID&gt;2&lt;/JE_HEADER_ID&gt;&lt;NAME&gt;Beta&lt;/NAME&gt;&lt;/ROW&gt;"
		    "&lt;/ROWSET&gt;"));
	}

private:
	Script &script;
};

ScopedTransportFactory InstallCatalog(Script &script) {
	return ScopedTransportFactory(
	    [&script](const FusionConfig &) { return std::make_shared<CatalogTransport>(script); });
}

void Attach(Connection &connection) {
	auto result = connection.Query("ATTACH 'fusion' AS fus (TYPE oracle_fusion)");
	if (result->HasError()) {
		std::cerr << "ATTACH failed: " << result->GetError() << std::endl;
		std::abort();
	}
}

//! ATTACH must be free. The schema is fixed and the secret is already known, so
//! there is nothing to ask Fusion -- and a multi-second ATTACH would be felt on
//! every session start.
//! ATTACH takes the query function's options. They have to be taken away
//! again before DuckDB's own storage layer sees them: it opens a local
//! StorageManager for the catalog and refuses any option it does not know,
//! which is how FETCH_SIZE was "Unrecognized option for attach".
void TestAttachOptionsReachTheScan() {
	ResetCache();
	Script script;
	auto installed = InstallCatalog(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	RunQuery(connection, "ATTACH 'fusion' AS fus (TYPE oracle_fusion, FETCH_SIZE 2000)");
	RunQuery(connection, "SELECT NAME FROM fus.main.GL_JE_HEADERS");

	bool paged_as_asked = false;
	for (const auto &sql : script.executed_sql) {
		if (sql.find("FROM \"GL_JE_HEADERS\"") != std::string::npos &&
		    sql.find("FETCH FIRST 2000 ROWS ONLY") != std::string::npos) {
			paged_as_asked = true;
		}
	}
	CHECK(paged_as_asked);
}

void TestAttachCostsNoRequests() {
	ResetCache();
	Script script;
	auto installed = InstallCatalog(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	Attach(connection);

	CHECK(script.executed_sql.empty());
}

//! Catalog lookup and the metadata table functions share one page-size
//! resolver, so the connection setting cannot silently diverge between them.
void TestAttachedCatalogHonoursMetadataPageSize() {
	ResetCache();
	Script script;
	auto installed = InstallCatalog(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto default_size = RunQuery(connection, "SELECT current_setting('fusion_scanner_metadata_page_size')");
	CHECK(default_size->GetValue(0, 0).GetValue<uint64_t>() == ofquack::metadata::TABLE_LIST_PAGE_SIZE);
	RunQuery(connection, "SET fusion_scanner_metadata_page_size = 17");
	Attach(connection);
	RunQuery(connection, "SELECT NAME FROM fus.main.GL_JE_HEADERS");

	bool used_setting = false;
	for (const auto &sql : script.executed_sql) {
		used_setting = used_setting ||
		               (sql.find("FND_VIEWS") != std::string::npos &&
		                sql.find("FETCH FIRST 17 ROWS ONLY") != std::string::npos);
	}
	CHECK(used_setting);
}

void TestSelectFromAttachedTable() {
	ResetCache();
	Script script;
	auto installed = InstallCatalog(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	Attach(connection);

	auto result = RunQuery(connection, "SELECT * FROM fus.main.GL_JE_HEADERS ORDER BY JE_HEADER_ID");
	CHECK(result->RowCount() == 2);
	CHECK(result->ColumnCount() == 2);
	// The types come from Fusion's dictionary, not from looking at the data.
	CHECK(result->types[0] == duckdb::LogicalType::INTEGER);
	CHECK(result->types[1] == duckdb::LogicalType::VARCHAR);
	CHECK(result->GetValue(1, 0).ToString() == "Alpha");
}

//! Every selected column travels back as base64-encoded XML, so a projection is
//! a bandwidth decision rather than a micro-optimisation.
void TestProjectionReachesTheStatement() {
	ResetCache();
	Script script;
	auto installed = InstallCatalog(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	Attach(connection);
	RunQuery(connection, "SELECT NAME FROM fus.main.GL_JE_HEADERS");

	// The last statement is the scan; earlier ones are dictionary reads.
	const auto &scan_sql = script.executed_sql.back();
	CHECK(scan_sql.find("FROM \"GL_JE_HEADERS\"") != std::string::npos);
	// The select list carries the projected column, plus the key the paged
	// read seeks by -- it has to be read back from each page -- and nothing
	// else. Of the table's columns, only those two travel back.
	const auto select_list = scan_sql.substr(0, scan_sql.find(" FROM "));
	CHECK(select_list == "SELECT \"NAME\", \"JE_HEADER_ID\"");
}

void TestCountStarReadsOneColumnAndEmitsNone() {
	ResetCache();
	Script script;
	auto installed = InstallCatalog(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	Attach(connection);

	auto result = RunQuery(connection, "SELECT count(*) FROM fus.main.GL_JE_HEADERS");
	CHECK(result->GetValue(0, 0).GetValue<int64_t>() == 2);
	// Oracle needs a select list even when no values are wanted.
	CHECK(script.executed_sql.back().find("SELECT ") == 0);
}

//! DuckDB removes a filter it has handed to a scan, so pushing one that cannot
//! be translated exactly would silently change the answer. Off by default.
//! A Fusion table often has no declared primary key but does have a unique
//! index; its columns, in position order, are the key a paged read seeks by.
//! Narrowest first, since a one-column key is the cheapest seek.
void TestUniqueIndexesArriveGroupedAndNarrowestFirst() {
	Script script;
	script.response = MakeSoapResponse(MakeReportXML(
	    "&lt;ROWSET&gt;"
	    "&lt;ROW&gt;&lt;INDEX_NAME&gt;AP_INVOICES_U2&lt;/INDEX_NAME&gt;&lt;ORDINAL_POSITION&gt;2&lt;/ORDINAL_POSITION&gt;"
	    "&lt;COLUMN_NAME&gt;INVOICE_NUM&lt;/COLUMN_NAME&gt;&lt;/ROW&gt;"
	    "&lt;ROW&gt;&lt;INDEX_NAME&gt;AP_INVOICES_U2&lt;/INDEX_NAME&gt;&lt;ORDINAL_POSITION&gt;1&lt;/ORDINAL_POSITION&gt;"
	    "&lt;COLUMN_NAME&gt;VENDOR_ID&lt;/COLUMN_NAME&gt;&lt;/ROW&gt;"
	    "&lt;ROW&gt;&lt;INDEX_NAME&gt;AP_INVOICES_U1&lt;/INDEX_NAME&gt;&lt;ORDINAL_POSITION&gt;1&lt;/ORDINAL_POSITION&gt;"
	    "&lt;COLUMN_NAME&gt;INVOICE_ID&lt;/COLUMN_NAME&gt;&lt;/ROW&gt;"
	    "&lt;/ROWSET&gt;"));
	FakeTransport transport(script, FusionConfig());

	const auto indexes = ofquack::FetchUniqueIndexes(transport, RequestContext(), ofquack::metadata::DICTIONARY_SCHEMA, "AP_INVOICES_ALL");

	CHECK(indexes.size() == 2);
	CHECK(indexes[0].name == "AP_INVOICES_U1");
	CHECK(indexes[0].columns.size() == 1);
	CHECK(indexes[0].columns[0] == "INVOICE_ID");
	CHECK(indexes[1].name == "AP_INVOICES_U2");
	CHECK(indexes[1].columns.size() == 2);
	CHECK(indexes[1].columns[0] == "VENDOR_ID");
	CHECK(indexes[1].columns[1] == "INVOICE_NUM");
	CHECK(script.executed_sql.size() == 1);
	CHECK(script.executed_sql[0].find("uniqueness = 'UNIQUE'") != std::string::npos);
}

//! Listing the schema must not freeze it. DuckDB stops consulting a default
//! generator once a scan has asked it for everything; with a listing that is
//! deliberately partial, a table first named after the listing -- after the
//! client expanded the table tree, say -- "did not exist". PO_LINES_ALL did
//! not exist on a live instance, right after XLA_AE_LINES had worked.
void TestTableIsFoundAfterTheSchemaWasListed() {
	ResetCache();
	Script script;
	auto installed = InstallCatalog(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	Attach(connection);

	// A cold cache: the listing has nothing describable to offer, so the scan
	// produces no entries and marks the generator as exhausted.
	auto listed = RunQuery(connection, "SELECT table_name FROM duckdb_tables() WHERE database_name = 'fus'");
	CHECK(listed->RowCount() == 0);

	// The table is still there when asked for by name.
	auto result = RunQuery(connection, "SELECT NAME FROM fus.main.GL_JE_HEADERS ORDER BY NAME");
	CHECK(result->RowCount() == 2);
	CHECK(result->GetValue(0, 0).ToString() == "Alpha");

	// And, once described, it appears in the listing.
	auto relisted = RunQuery(connection, "SELECT table_name FROM duckdb_tables() WHERE database_name = 'fus'");
	CHECK(relisted->RowCount() == 1);
}

//! The paged scan of an attached table orders by its primary key -- walked
//! through an index, so a page costs a page -- and not by every column, which
//! sorted all of XLA_AE_LINES for its first 500 rows and never came back.
void TestAttachedScanOrdersByThePrimaryKey() {
	ResetCache();
	Script script;
	auto installed = InstallCatalog(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	RunQuery(connection, "ATTACH 'fusion' AS fus (TYPE oracle_fusion)");
	RunQuery(connection, "SELECT NAME FROM fus.main.GL_JE_HEADERS");

	bool first_page_by_key = false;
	bool next_page_sought = false;
	bool asked_for_key = false;
	for (const auto &sql : script.executed_sql) {
		if (sql.find("all_constraints") != std::string::npos) {
			asked_for_key = true;
		}
		// The first page: key order, no OFFSET. The key travels with the page
		// even though only NAME was asked for, because the seek reads it back.
		if (sql.find("SELECT \"NAME\", \"JE_HEADER_ID\" FROM \"GL_JE_HEADERS\" ORDER BY \"JE_HEADER_ID\" FETCH FIRST "
		             "500 ROWS ONLY") != std::string::npos) {
			first_page_by_key = true;
		}
		// The next: everything after the last row seen, not everything after
		// a count of rows. That is what keeps a page's cost flat.
		if (sql.find("WHERE (\"JE_HEADER_ID\" > 2) ORDER BY \"JE_HEADER_ID\" FETCH FIRST 500 ROWS ONLY") !=
		    std::string::npos) {
			next_page_sought = true;
		}
		if (sql.find("FROM \"GL_JE_HEADERS\"") != std::string::npos) {
			CHECK(sql.find("OFFSET") == std::string::npos);
		}
		// Never by position: the key is not among the selected columns here,
		// and a positional order over NAME alone would not be a total order.
		CHECK(sql.find("ORDER BY 1") == std::string::npos);
	}
	CHECK(asked_for_key);
	CHECK(first_page_by_key);
	CHECK(next_page_sought);

	// The key is cached with the rest of the dictionary: a second scan, from
	// a new connection, does not ask for it again.
	const auto after_first = script.executed_sql.size();
	Connection second(db);
	RunQuery(second, "SELECT NAME FROM fus.main.GL_JE_HEADERS");
	for (size_t i = after_first; i < script.executed_sql.size(); i++) {
		CHECK(script.executed_sql[i].find("all_constraints") == std::string::npos);
	}
}

//! DuckDB materialises an attached table's schema. If that metadata is
//! invalidated later, silently scanning with the old schema is unsafe; the
//! catalog requires a reattach and succeeds again afterwards.
void TestAttachedEntryRejectsInvalidatedMetadata() {
	ResetCache();
	Script script;
	auto installed = InstallCatalog(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	Attach(connection);
	RunQuery(connection, "SELECT NAME FROM fus.main.GL_JE_HEADERS");

	RunQuery(connection, "SELECT * FROM fusion_scanner_cache_invalidate(table_name := 'GL_JE_HEADERS')");
	auto stale = connection.Query("SELECT NAME FROM fus.main.GL_JE_HEADERS");
	CHECK(stale->HasError());
	CHECK(stale->GetError().find("DETACH") != std::string::npos);

	RunQuery(connection, "DETACH fus");
	Attach(connection);
	auto fresh = RunQuery(connection, "SELECT NAME FROM fus.main.GL_JE_HEADERS ORDER BY NAME");
	CHECK(fresh->RowCount() == 2);
}

//! SynchronizeColumns erases the old in-memory vector when the cache revision
//! changes. A caller that retained the previous Columns() result must still be
//! able to read that snapshot after a repeated lookup observes the new one.
void TestRetainedCatalogColumnsSurviveInvalidation() {
	ResetCache();
	DuckDB db(nullptr);
	Connection connection(db);
	CHECK(duckdb::CatalogColumnsSurviveInvalidationForTesting(*connection.context));
}

void TestFilterPushdownIsOffByDefault() {
	ResetCache();
	Script script;
	auto installed = InstallCatalog(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	Attach(connection);
	RunQuery(connection, "SELECT NAME FROM fus.main.GL_JE_HEADERS WHERE JE_HEADER_ID = 1");

	// No statement carries the predicate. A WHERE as such is not the test:
	// the seek that pages the table writes one of its own.
	for (const auto &sql : script.executed_sql) {
		CHECK(sql.find("= 1") == std::string::npos);
	}
}

void TestFilterPushdownWhenEnabled() {
	ResetCache();
	Script script;
	auto installed = InstallCatalog(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	Attach(connection);
	RunQuery(connection, "SET fusion_scanner_filter_pushdown = true");
	RunQuery(connection, "SELECT NAME FROM fus.main.GL_JE_HEADERS WHERE JE_HEADER_ID = 1");

	const auto &scan_sql = script.executed_sql.back();
	CHECK(scan_sql.find("WHERE") != std::string::npos);
	CHECK(scan_sql.find("\"JE_HEADER_ID\" = 1") != std::string::npos);
}

//! Ordering text depends on NLS_SORT, which this connection does not negotiate,
//! so the comparison Oracle would make need not be the one DuckDB would.
void TestUntranslatableFilterIsRefusedRatherThanApproximated() {
	ResetCache();
	Script script;
	auto installed = InstallCatalog(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	Attach(connection);
	RunQuery(connection, "SET fusion_scanner_filter_pushdown = true");

	auto result = connection.Query("SELECT NAME FROM fus.main.GL_JE_HEADERS WHERE NAME > 'M'");
	CHECK(result->HasError());
	CHECK(result->GetError().find("fusion_scanner_filter_pushdown") != std::string::npos);
}

void TestAttachedCatalogIsReadOnly() {
	ResetCache();
	Script script;
	auto installed = InstallCatalog(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	Attach(connection);

	for (const auto *statement : {"INSERT INTO fus.main.GL_JE_HEADERS VALUES (3, 'Gamma')",
	                              "CREATE TABLE fus.main.T (a INTEGER)", "DELETE FROM fus.main.GL_JE_HEADERS",
	                              "UPDATE fus.main.GL_JE_HEADERS SET NAME = 'x'", "CREATE SCHEMA fus.other"}) {
		auto result = connection.Query(statement);
		CHECK(result->HasError());
		// A clear refusal, not an internal error -- an InternalException would
		// mark the database invalid and kill the connection.
		CHECK(result->GetError().find("Internal Error") == std::string::npos);
	}

	// The connection still works afterwards.
	auto after = RunQuery(connection, "SELECT count(*) FROM fus.main.GL_JE_HEADERS");
	CHECK(after->GetValue(0, 0).GetValue<int64_t>() == 2);
}

//! A table Fusion lists but cannot describe must say so. Reporting it as
//! non-existent sends the user looking for a typo in a name that is correct.
void TestListedButUndescribableTableIsExplained() {
	ResetCache();
	struct NoColumnsTransport : FusionTransport {
		std::string Execute(const std::string &sql, const RequestContext &) override {
			if (AsksForALaterPage(sql)) {
				return MakeSoapResponse(MakeReportXML("&lt;ROWSET/&gt;"));
			}
			if (sql.find("FND_VIEWS") != std::string::npos) {
				return MakeSoapResponse(MakeReportXML(
				    "&lt;ROWSET&gt;&lt;ROW&gt;&lt;TABLE_NAME&gt;XLA_AE_LINES&lt;/TABLE_NAME&gt;"
				    "&lt;TABLE_TYPE&gt;TABLE&lt;/TABLE_TYPE&gt;&lt;TABLE_ID&gt;77&lt;/TABLE_ID&gt;&lt;/ROW&gt;"
				    "&lt;/ROWSET&gt;"));
			}
			// The dictionary knows the table but has no columns for it.
			return MakeSoapResponse(MakeReportXML("&lt;ROWSET/&gt;"));
		}
	};
	ScopedTransportFactory installed([](const FusionConfig &) { return std::make_shared<NoColumnsTransport>(); });

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	Attach(connection);

	auto result = connection.Query("SELECT * FROM fus.main.XLA_AE_LINES");
	CHECK(result->HasError());
	const auto message = result->GetError();
	CHECK(message.find("XLA_AE_LINES") != std::string::npos);
	// Not "does not exist", and it points at a way to get the data anyway.
	CHECK(message.find("no column information") != std::string::npos);
	CHECK(message.find("oracle_fusion_query") != std::string::npos);
}

//! A name that belongs to no attached catalog must come back as "not found",
//! not as an error from ours: DuckDB asks every catalog about every name.
void TestUnknownTableInAttachedCatalog() {
	ResetCache();
	Script script;
	auto installed = InstallCatalog(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	Attach(connection);

	auto result = connection.Query("SELECT * FROM fus.main.NO_SUCH_TABLE");
	CHECK(result->HasError());
	CHECK(result->GetError().find("NO_SUCH_TABLE") != std::string::npos);
}

//! SHOW TABLES lists only tables whose columns are known.
//!
//! DuckDB treats a name offered by the generator and then not created as an
//! internal error that aborts the scan -- and Fusion's dictionary lists plenty
//! of objects with no rows in FND_COLUMNS. Listing a table before its columns
//! are known therefore risks taking down every catalog browser, so the list is
//! restricted to what can actually be described.
//! A schema tree is expected to hold the schema's tables. Listing only the ones
//! whose columns had already been read meant a freshly attached catalog looked
//! empty on an instance with 28,978 objects, and no amount of querying made it
//! look otherwise except one table at a time.
void TestShowTablesListsEveryTableInTheDictionary() {
	ResetCache();
	Script script;
	auto installed = InstallCatalog(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	Attach(connection);

	// ATTACH still costs nothing, and a cold catalog lists nothing: the tree is
	// answered from the cache, never from the network.
	CHECK(script.executed_sql.empty());
	auto cold = RunQuery(connection, "SELECT count(*) FROM duckdb_tables() WHERE database_name = 'fus'");
	CHECK(cold->GetValue(0, 0).GetValue<int64_t>() == 0);

	// One call puts the dictionary on disk. That is all the tree needs.
	RunQuery(connection, "SELECT * FROM oracle_fusion_tables()");
	const auto after_listing = script.executed_sql.size();

	auto listed = RunQuery(connection, "SELECT table_name FROM duckdb_tables() WHERE database_name = 'fus'");
	CHECK(listed->RowCount() == 1);
	CHECK(listed->GetValue(0, 0).ToString() == "GL_JE_HEADERS");

	// Listing must not have fetched anybody's columns -- that is one request per
	// table, and there are tens of thousands of them on a real instance.
	CHECK(script.executed_sql.size() == after_listing);

	// And a listed table is queryable: its real columns arrive when it is used.
	auto rows = RunQuery(connection, "SELECT NAME FROM fus.main.GL_JE_HEADERS");
	CHECK(rows->RowCount() == 2);
	CHECK(rows->names[0] == "NAME");
}

//! Warming reports what it did, and does not refetch what it already has.
void TestCacheWarm() {
	ResetCache();
	Script script;
	auto installed = InstallDictionary(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);

	auto first = RunQuery(connection, "SELECT tables_warmed, columns_cached, already_cached FROM "
	                                  "fusion_scanner_cache_warm(pattern := '%')");
	CHECK(first->GetValue(0, 0).GetValue<int64_t>() == 2); // one table, one view
	CHECK(first->GetValue(1, 0).GetValue<int64_t>() == 3); // two columns plus one
	CHECK(first->GetValue(2, 0).GetValue<int64_t>() == 0);
	const auto after_first = script.executed_sql.size();

	// A second warm has nothing left to do.
	auto second = RunQuery(connection,
	                       "SELECT tables_warmed, already_cached FROM fusion_scanner_cache_warm(pattern := '%')");
	CHECK(second->GetValue(0, 0).GetValue<int64_t>() == 0);
	CHECK(second->GetValue(1, 0).GetValue<int64_t>() == 2);
	CHECK(script.executed_sql.size() == after_first);
}

//! Thirty thousand tables is hours of SOAP calls, so a warm is bounded and can
//! be aimed at the tables actually of interest.
void TestCacheWarmPatternAndLimit() {
	ResetCache();
	Script script;
	auto installed = InstallDictionary(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);

	auto result = RunQuery(connection, "SELECT tables_warmed FROM fusion_scanner_cache_warm(pattern := 'GL_JE%')");
	CHECK(result->GetValue(0, 0).GetValue<int64_t>() == 1);

	ResetCache();
	auto limited = RunQuery(
	    connection, "SELECT tables_warmed FROM fusion_scanner_cache_warm(pattern := '%', max_tables := 1)");
	CHECK(limited->GetValue(0, 0).GetValue<int64_t>() == 1);

	auto missing_pattern = connection.Query("SELECT * FROM fusion_scanner_cache_warm()");
	CHECK(missing_pattern->HasError());
	CHECK(missing_pattern->GetError().find("pattern is required") != std::string::npos);

	auto invalid = connection.Query("SELECT * FROM fusion_scanner_cache_warm(pattern := '%', max_tables := -1)");
	CHECK(invalid->HasError());
	CHECK(invalid->GetError().find("max_tables") != std::string::npos);
}

//! The documented backslash escape makes '_' literal, and a cold warm honours
//! the configured table-list page size instead of silently using 400.
void TestCacheWarmPatternEscapeAndPageSize() {
	ResetCache();
	Script script;
	auto installed = InstallDictionary(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	RunQuery(connection, "SET fusion_scanner_metadata_page_size = 17");
	auto result = RunQuery(connection,
	                       "SELECT tables_warmed FROM fusion_scanner_cache_warm(pattern := 'GL\\_JE%')");
	CHECK(result->GetValue(0, 0).GetValue<int64_t>() == 1);

	bool used_setting = false;
	for (const auto &sql : script.executed_sql) {
		used_setting = used_setting ||
		               (sql.find("FND_VIEWS") != std::string::npos && sql.find("FETCH FIRST 17 ROWS ONLY") != std::string::npos);
	}
	CHECK(used_setting);
}

//! A table for which FND_COLUMNS returns nothing is still a completed lookup.
//! The warmer records the empty answer so repeated runs do not hit Fusion.
void TestCacheWarmRecordsEmptyTableColumns() {
	ResetCache();
	Script script;
	struct EmptyColumnsTransport : FusionTransport {
		Script &script;
		explicit EmptyColumnsTransport(Script &script_p) : script(script_p) {
		}
		std::string Execute(const std::string &sql, const RequestContext &) override {
			script.executed_sql.push_back(sql);
			if (sql.find("COUNT(DISTINCT") != std::string::npos) {
				return MakeSoapResponse(MakeReportXML(
				    "&lt;ROWSET&gt;&lt;ROW&gt;&lt;TABLE_COUNT&gt;1&lt;/TABLE_COUNT&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));
			}
			if (sql.find("FND_VIEWS") != std::string::npos && !AsksForALaterPage(sql)) {
				return MakeSoapResponse(MakeReportXML(
				    "&lt;ROWSET&gt;&lt;ROW&gt;&lt;TABLE_NAME&gt;EMPTY_T&lt;/TABLE_NAME&gt;"
				    "&lt;TABLE_TYPE&gt;TABLE&lt;/TABLE_TYPE&gt;&lt;TABLE_ID&gt;7&lt;/TABLE_ID&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));
			}
			return MakeSoapResponse(MakeReportXML("&lt;ROWSET/&gt;"));
		}
	};
	ScopedTransportFactory installed(
	    [&script](const FusionConfig &) { return std::make_shared<EmptyColumnsTransport>(script); });

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto first = RunQuery(connection,
	                      "SELECT tables_without_columns FROM fusion_scanner_cache_warm(pattern := 'EMPTY\\_T')");
	CHECK(first->GetValue(0, 0).GetValue<int64_t>() == 1);
	const auto requests_after_first = script.executed_sql.size();
	auto second = RunQuery(connection, "SELECT already_cached FROM fusion_scanner_cache_warm(pattern := 'EMPTY\\_T')");
	CHECK(second->GetValue(0, 0).GetValue<int64_t>() == 1);
	CHECK(script.executed_sql.size() == requests_after_first);
}

//! A view is not in FND_COLUMNS and so costs a request of its own. A warm that
//! reaches its last view has already spent one per view, and an error there
//! used to discard every one of them: the columns were held in memory until the
//! whole loop finished. What has arrived is now written on the way out, so the
//! retry pays only for what is still missing.
void TestCacheWarmKeepsViewColumnsWhenItFails() {
	ResetCache();
	struct FailingViewTransport : FusionTransport {
		bool fail_second_view = true;
		std::string Execute(const std::string &sql, const RequestContext &) override {
			if (sql.find("COUNT(DISTINCT") != std::string::npos) {
				return MakeSoapResponse(MakeReportXML(
				    "&lt;ROWSET&gt;&lt;ROW&gt;&lt;TABLE_COUNT&gt;2&lt;/TABLE_COUNT&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));
			}
			if (sql.find("all_tab_columns") != std::string::npos) {
				if (AsksForALaterPage(sql)) {
					return MakeSoapResponse(MakeReportXML("&lt;ROWSET/&gt;"));
				}
				if (fail_second_view && sql.find("WARM_V2") != std::string::npos) {
					throw ofquack::RetryableError("BI Publisher is busy");
				}
				const auto name = sql.find("WARM_V2") != std::string::npos ? "WARM_V2" : "WARM_V1";
				return MakeSoapResponse(MakeReportXML(
				    std::string("&lt;ROWSET&gt;&lt;ROW&gt;&lt;TABLE_NAME&gt;") + name +
				    "&lt;/TABLE_NAME&gt;&lt;COLUMN_NAME&gt;C1&lt;/COLUMN_NAME&gt;"
				    "&lt;TYPE_NAME&gt;VARCHAR2&lt;/TYPE_NAME&gt;"
				    "&lt;ORDINAL_POSITION&gt;1&lt;/ORDINAL_POSITION&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));
			}
			if (AsksForALaterPage(sql)) {
				return MakeSoapResponse(MakeReportXML("&lt;ROWSET/&gt;"));
			}
			return MakeSoapResponse(
			    MakeReportXML("&lt;ROWSET&gt;"
			                  "&lt;ROW&gt;&lt;TABLE_NAME&gt;WARM_V1&lt;/TABLE_NAME&gt;"
			                  "&lt;TABLE_TYPE&gt;VIEW&lt;/TABLE_TYPE&gt;&lt;TABLE_ID&gt;&lt;/TABLE_ID&gt;&lt;/ROW&gt;"
			                  "&lt;ROW&gt;&lt;TABLE_NAME&gt;WARM_V2&lt;/TABLE_NAME&gt;"
			                  "&lt;TABLE_TYPE&gt;VIEW&lt;/TABLE_TYPE&gt;&lt;TABLE_ID&gt;&lt;/TABLE_ID&gt;&lt;/ROW&gt;"
			                  "&lt;/ROWSET&gt;"));
		}
	};
	auto transport = std::make_shared<FailingViewTransport>();
	ScopedTransportFactory installed([transport](const FusionConfig &) { return transport; });

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);

	// Two views, and the second one refuses. Fewer than a batch, so nothing was
	// written before the failure -- which is exactly the case that used to lose
	// everything.
	auto failed = connection.Query("SELECT * FROM fusion_scanner_cache_warm(pattern := 'WARM\\_V%')");
	CHECK(failed->HasError());

	transport->fail_second_view = false;
	auto retry = RunQuery(connection, "SELECT tables_warmed, already_cached FROM "
	                                  "fusion_scanner_cache_warm(pattern := 'WARM\\_V%')");
	// The first view survived the failure; only the second is fetched again.
	CHECK(retry->GetValue(1, 0).GetValue<int64_t>() == 1);
	CHECK(retry->GetValue(0, 0).GetValue<int64_t>() == 1);
}

//! An instance that will not count its own dictionary leaves the list
//! unverifiable, so it is not cached -- and warming columns against a list
//! nothing can read back is pointless. Refusing is right; blaming the cache
//! file for it sent the user looking at the wrong machine.
void TestCacheWarmNamesTheMissingCount() {
	ResetCache();
	struct NoCountTransport : FusionTransport {
		std::string Execute(const std::string &sql, const RequestContext &) override {
			if (sql.find("COUNT(DISTINCT") != std::string::npos) {
				throw ofquack::PermanentError("ORA-00942: table or view does not exist");
			}
			if (AsksForALaterPage(sql)) {
				return MakeSoapResponse(MakeReportXML("&lt;ROWSET/&gt;"));
			}
			return MakeSoapResponse(MakeReportXML(
			    "&lt;ROWSET&gt;&lt;ROW&gt;&lt;TABLE_NAME&gt;T&lt;/TABLE_NAME&gt;&lt;TABLE_TYPE&gt;TABLE&lt;/TABLE_TYPE&gt;"
			    "&lt;TABLE_ID&gt;1&lt;/TABLE_ID&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));
		}
	};
	auto transport = std::make_shared<NoCountTransport>();
	ScopedTransportFactory installed([transport](const FusionConfig &) { return transport; });

	DuckDB db(nullptr);
	Connection connection(db);
	CreateSecret(connection);
	auto result = connection.Query("SELECT * FROM fusion_scanner_cache_warm(pattern := '%')");
	CHECK(result->HasError());
	// Names the count and where it comes from, not the cache.
	CHECK(result->GetError().find("would not count") != std::string::npos);
	CHECK(result->GetError().find("FND_TABLES") != std::string::npos);
	CHECK(result->GetError().find("metadata cache at") == std::string::npos);
}

// ---------------------------------------------------------------------------
// SSO
// ---------------------------------------------------------------------------

//! Note the absence of SSO_LOGIN_URL: it defaults to the endpoint's host, and
//! requiring it would be asking twice for one fact.
void CreateBrowserSecret(Connection &connection, const char *name = "sso") {
	auto result = connection.Query(std::string("CREATE SECRET ") + name +
	                               " (TYPE oracle_fusion, PROVIDER browser, "
	                               "ENDPOINT 'https://sso.example.com/xmlpserver/services/"
	                               "ExternalReportWSSService?WSDL', "
	                               "REPORT_PATH '/Custom/Financials/RP_ARB.xdo')");
	if (result->HasError()) {
		std::cerr << "CREATE SECRET failed: " << result->GetError() << std::endl;
		std::abort();
	}
}

//! Creating the secret must not open a browser: CREATE SECRET is routinely run
//! from a script, and an interactive step there would hang it.
void TestBrowserSecretIsCreatedWithoutSigningIn() {
	DuckDB db(nullptr);
	Connection connection(db);
	CreateBrowserSecret(connection);

	auto result = RunQuery(connection, "SELECT provider FROM duckdb_secrets() WHERE name = 'sso'");
	CHECK(result->RowCount() == 1);
	CHECK(result->GetValue(0, 0).ToString() == "browser");
}

//! A browser secret holds no credential at all -- that is the point of it.
void TestBrowserSecretHoldsNoCredential() {
	DuckDB db(nullptr);
	Connection connection(db);
	CreateBrowserSecret(connection);

	auto result = RunQuery(connection, "SELECT secret_string FROM duckdb_secrets() WHERE name = 'sso'");
	const auto rendered = result->GetValue(0, 0).ToString();
	CHECK(rendered.find("password") == std::string::npos);
	CHECK(rendered.find("sso.example.com") != std::string::npos);
}

void TestSsoStatusWithoutToken() {
	ofquack::TokenCache::Get().Clear();
	DuckDB db(nullptr);
	Connection connection(db);
	CreateBrowserSecret(connection);

	auto result = RunQuery(connection, "SELECT host, have_token, subject FROM fusion_scanner_sso_status()");
	CHECK(result->RowCount() == 1);
	CHECK(result->GetValue(0, 0).ToString() == "sso.example.com");
	CHECK(!result->GetValue(1, 0).GetValue<bool>());
	CHECK(result->GetValue(2, 0).IsNull());
}

//! Before browser login there is an endpoint but no authenticated principal.
//! Zero would claim knowledge about a cache key that no signed-in user uses.
void TestCacheStatusWithoutBrowserPrincipalIsUnknown() {
	ofquack::TokenCache::Get().Clear();
	ResetCache();
	DuckDB db(nullptr);
	Connection connection(db);
	CreateBrowserSecret(connection);

	auto status = RunQuery(connection,
	                       "SELECT endpoint, principal, cached_tables, dictionary_tables, complete, cached_columns, "
	                       "fresh_tables, fresh_columns, described_tables "
	                       "FROM fusion_scanner_cache_status(secret := 'sso')");
	CHECK(!status->GetValue(0, 0).IsNull());
	for (idx_t column = 1; column < status->ColumnCount(); column++) {
		CHECK(status->GetValue(column, 0).IsNull());
	}
}

//! A query on a browser secret with no token says how to sign in rather than
//! opening a window by itself: a SELECT must never become interactive.
void TestBearerQueryWithoutTokenExplainsHowToSignIn() {
	ofquack::TokenCache::Get().Clear();
	Script script;
	script.response = MakeSoapResponse(MakeReportXML(TWO_ROWS));
	auto installed = InstallFake(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateBrowserSecret(connection);

	auto result = connection.Query("SELECT * FROM oracle_fusion_query('SELECT NAME FROM T', secret := 'sso')");
	CHECK(result->HasError());
	CHECK(result->GetError().find("fusion_scanner_sso_login") != std::string::npos);
	// Nothing was sent: the request never got as far as the transport.
	CHECK(script.executed_sql.empty());
}

//! A token obtained elsewhere works without any browser involvement, which is
//! also the escape hatch when the browser flow cannot run.
void TestBearerTokenFromSecretIsUsed() {
	ofquack::TokenCache::Get().Clear();
	Script script;
	script.response = MakeSoapResponse(MakeReportXML(TWO_ROWS));
	auto installed = InstallFake(script);

	DuckDB db(nullptr);
	Connection connection(db);
	auto created = connection.Query("CREATE SECRET bearer_secret (TYPE oracle_fusion, "
	                                "ENDPOINT 'https://bearer.example.com/x?WSDL', REPORT_PATH '/r.xdo', "
	                                "AUTH 'bearer', TOKEN 'header.payload.signature')");
	CHECK(!created->HasError());

	auto result = RunQuery(connection, "SELECT * FROM oracle_fusion_query('SELECT NAME, CODE FROM T', "
	                                   "secret := 'bearer_secret')");
	CHECK(result->RowCount() == 2);
	CHECK(script.configs.size() == 1);
	CHECK(script.configs[0].auth == ofquack::AuthMode::BEARER);
	CHECK(script.configs[0].token == "header.payload.signature");
}

//! The token is never printed. It is a live credential, and a status view that
//! echoed it would put it into scrollback and query history.
void TestSsoStatusNeverPrintsTheToken() {
	ofquack::TokenCache::Get().Clear();
	ofquack::TokenCache::Get().Store("sso.example.com", "aaa.bbb.ccc", "refresh-token", 3600);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateBrowserSecret(connection);

	auto result = RunQuery(connection, "SELECT * FROM fusion_scanner_sso_status()");
	CHECK(result->GetValue(1, 0).GetValue<bool>()); // have_token
	for (duckdb::idx_t column = 0; column < result->ColumnCount(); column++) {
		const auto rendered = result->GetValue(column, 0).ToString();
		CHECK(rendered.find("aaa.bbb.ccc") == std::string::npos);
		CHECK(rendered.find("refresh-token") == std::string::npos);
	}
	ofquack::TokenCache::Get().Clear();
}

void TestSsoLogoutDiscardsTheToken() {
	ofquack::TokenCache::Get().Clear();
	ofquack::TokenCache::Get().Store("sso.example.com", "aaa.bbb.ccc", "", 3600);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateBrowserSecret(connection);

	auto result = RunQuery(connection, "SELECT token_discarded FROM fusion_scanner_sso_logout()");
	CHECK(result->GetValue(0, 0).GetValue<bool>());

	auto status = RunQuery(connection, "SELECT have_token FROM fusion_scanner_sso_status()");
	CHECK(!status->GetValue(0, 0).GetValue<bool>());
}

//! A cached token is used without a browser, which is what makes the flow
//! bearable: signing in once covers every later query.
void TestCachedTokenIsUsedForQueries() {
	ofquack::TokenCache::Get().Clear();
	ofquack::TokenCache::Get().Store("sso.example.com", "aaa.bbb.ccc", "", 3600);

	Script script;
	script.response = MakeSoapResponse(MakeReportXML(TWO_ROWS));
	auto installed = InstallFake(script);

	DuckDB db(nullptr);
	Connection connection(db);
	CreateBrowserSecret(connection);

	auto result = RunQuery(connection, "SELECT * FROM oracle_fusion_query('SELECT NAME, CODE FROM T', "
	                                   "secret := 'sso')");
	CHECK(result->RowCount() == 2);
	CHECK(script.configs[0].auth == ofquack::AuthMode::BEARER);
	ofquack::TokenCache::Get().Clear();
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
    {"unknown auth mode is reported", TestUnknownAuthModeIsReported},
    {"secret with no credential names both possibilities", TestSecretWithNoCredentialNamesBothPossibilities},
    {"metadata failure shows what arrived", TestMetadataFailureShowsWhatArrived},
    {"bare host endpoint is completed", TestBareHostEndpointIsCompleted},
    {"full endpoint is left alone", TestFullEndpointIsLeftAlone},
    {"paging fetches every row in exactly the right number of requests", TestPagingFetchesEveryRowInExactlyTheRightNumberOfRequests},
    {"a short first page is confirmed, not assumed", TestShortFirstPageIsConfirmed},
    {"a paged statement is ordered", TestPagedStatementIsOrdered},
    {"a statement with its own order is not wrapped", TestStatementWithItsOwnOrderIsNotWrapped},
    {"order skips columns oracle refuses to sort", TestOrderSkipsColumnsOracleRefusesToSort},
    {"stable paging can be turned off", TestStablePagingCanBeTurnedOff},
    {"a repeated page is refused", TestARepeatedPageIsRefused},
    {"a truncated page is continued from", TestTruncatedPageIsContinuedFrom},
    {"a truncated response without paging is an error", TestTruncatedResponseWithoutPagingIsAnError},
    {"exactly full page costs one extra request", TestExactlyFullPageCostsOneExtraRequest},
    {"paging can be disabled", TestPagingCanBeDisabled},
    {"statement with its own limit is not rewritten", TestStatementWithItsOwnLimitIsNotRewritten},
    {"types are inferred from the first page", TestTypesAreInferredFromTheFirstPage},
    {"all_varchar disables inference", TestAllVarcharDisablesInference},
    {"contradicting value becomes null", TestValueThatContradictsTheInferredTypeBecomesNull},
    {"nulls in typed columns", TestNullsInTypedColumns},
    {"hint survives to the wire", TestHintSurvivesToTheWire},
    {"list tables", TestListTables},
    {"truncated page does not end the listing", TestTruncatedPageDoesNotEndTheListing},
    {"empty page is retried on a fresh session", TestEmptyPageIsRetriedOnAFreshSession},
    {"short listing is reported rather than cached", TestShortListingIsReportedRatherThanCached},
    {"unverified listing is not cached", TestUnverifiedListingIsNotCached},
    {"second listing costs nothing", TestSecondListingCostsNothing},
    {"an empty column list is cached", TestAnEmptyColumnListIsCached},
    {"refresh bypasses the cache", TestRefreshBypassesTheCache},
    {"invalidate forces a refetch", TestInvalidateForcesARefetch},
    {"invalidate removes expected count and order keys", TestInvalidateRemovesExpectedCountAndOrderKeys},
    {"columns of table and view", TestColumnsOfTableAndView},
    {"metadata short page ends immediately", TestMetadataShortPageEndsImmediately},
    {"metadata column page size controls query and completion", TestMetadataColumnPageSizeControlsQueryAndCompletion},
    {"metadata truncated short page continues", TestMetadataTruncatedShortPageContinues},
    {"unconstrained number is double", TestUnconstrainedNumberIsDouble},
    {"unknown table is reported", TestUnknownTableIsReported},
    {"cache status reports mode", TestCacheStatusReportsMode},
    {"population mutex is released after its users", TestPopulationMutexIsReleasedAfterItsUsers},
    {"cache status does not call unknown complete", TestCacheStatusDoesNotCallUnknownComplete},
    {"cache is keyed by endpoint", TestCacheIsKeyedByEndpoint},
    {"cache is keyed by principal", TestCacheIsKeyedByPrincipal},
    {"secret schema reaches the dictionary queries", TestSecretSchemaReachesTheDictionaryQueries},
    {"declared columns", TestDeclaredColumns},
    {"cast error mode in query function", TestCastErrorModeInQueryFunction},
    {"cast error mode in attached catalog", TestCastErrorModeInAttachedCatalog},
    {"secured views rewrite is applied", TestSecuredViewsRewriteIsApplied},
    {"secured views is off by default", TestSecuredViewsIsOffByDefault},
    {"attach options reach the scan", TestAttachOptionsReachTheScan},
    {"attach costs no requests", TestAttachCostsNoRequests},
    {"attached catalog honours metadata page size", TestAttachedCatalogHonoursMetadataPageSize},
    {"select from attached table", TestSelectFromAttachedTable},
    {"projection reaches the statement", TestProjectionReachesTheStatement},
    {"count star reads one column and emits none", TestCountStarReadsOneColumnAndEmitsNone},
    {"unique indexes arrive grouped and narrowest first", TestUniqueIndexesArriveGroupedAndNarrowestFirst},
    {"table is found after the schema was listed", TestTableIsFoundAfterTheSchemaWasListed},
    {"attached scan orders by the primary key", TestAttachedScanOrdersByThePrimaryKey},
    {"attached entry rejects invalidated metadata", TestAttachedEntryRejectsInvalidatedMetadata},
    {"retained catalog columns survive invalidation", TestRetainedCatalogColumnsSurviveInvalidation},
    {"filter pushdown is off by default", TestFilterPushdownIsOffByDefault},
    {"filter pushdown when enabled", TestFilterPushdownWhenEnabled},
    {"untranslatable filter is refused", TestUntranslatableFilterIsRefusedRatherThanApproximated},
    {"attached catalog is read-only", TestAttachedCatalogIsReadOnly},
    {"listed but undescribable table is explained", TestListedButUndescribableTableIsExplained},
    {"unknown table in attached catalog", TestUnknownTableInAttachedCatalog},
    {"show tables lists every table in the dictionary", TestShowTablesListsEveryTableInTheDictionary},
    {"cache warm", TestCacheWarm},
    {"cache warm pattern and limit", TestCacheWarmPatternAndLimit},
    {"cache warm pattern escape and page size", TestCacheWarmPatternEscapeAndPageSize},
    {"cache warm records empty table columns", TestCacheWarmRecordsEmptyTableColumns},
    {"cache warm keeps view columns when it fails", TestCacheWarmKeepsViewColumnsWhenItFails},
    {"cache warm names the missing count", TestCacheWarmNamesTheMissingCount},
    {"browser secret is created without signing in", TestBrowserSecretIsCreatedWithoutSigningIn},
    {"browser secret holds no credential", TestBrowserSecretHoldsNoCredential},
    {"sso status without token", TestSsoStatusWithoutToken},
    {"cache status without browser principal is unknown", TestCacheStatusWithoutBrowserPrincipalIsUnknown},
    {"bearer query without token explains how to sign in", TestBearerQueryWithoutTokenExplainsHowToSignIn},
    {"bearer token from secret is used", TestBearerTokenFromSecretIsUsed},
    {"sso status never prints the token", TestSsoStatusNeverPrintsTheToken},
    {"sso logout discards the token", TestSsoLogoutDiscardsTheToken},
    {"cached token is used for queries", TestCachedTokenIsUsedForQueries},
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
