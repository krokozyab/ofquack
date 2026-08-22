// Unit tests for the pure layer: envelope construction, report parsing and
// error decoding.
//
// Nothing here touches DuckDB or the network, so this binary builds and runs in
// about a second and can be run on every push.

#include "base64.h"
#include "ofquack/circuit_breaker.hpp"
#include "ofquack/error_decoder.hpp"
#include "ofquack/errors.hpp"
#include "ofquack/host_throttle.hpp"
#include "ofquack/retry.hpp"
#include "ofquack/browser_auth.hpp"
#include "ofquack/json_util.hpp"
#include "ofquack/jwt.hpp"
#include "ofquack/metadata_queries.hpp"
#include "ofquack/oracle_type_map.hpp"
#include "ofquack/secured_views.hpp"
#include "ofquack/soap_envelope.hpp"
#include "ofquack/sql_rewrite.hpp"
#include "ofquack/sql_text.hpp"
#include "ofquack/token_cache.hpp"
#include "ofquack/type_inference.hpp"
#include "ofquack/websocket.hpp"
#include "ofquack/xml_report.hpp"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

// A release build defines NDEBUG, and assert() then removes not just the check
// but the call inside it, so a suite written with assert silently stops testing
// in exactly the build that ships. CHECK always evaluates and always reports.
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

using ofquack::BuildEnvelope;
using ofquack::DescribeFailure;
using ofquack::EscapeCdata;
using ofquack::ExtractOracleErrors;
using ofquack::ComputeBackoffDelay;
using ofquack::ExtractReportXML;
using ofquack::ParseRows;

namespace {

bool Contains(const std::string &haystack, const std::string &needle) {
	return haystack.find(needle) != std::string::npos;
}

//! Wraps a report payload the way BI Publisher does: base64 inside <reportBytes>,
//! under a Body, with namespace prefixes that differ from the envelope's.
std::string MakeSoapResponse(const std::string &report_xml, const std::string &prefix = "ns2:") {
	const auto encoded = base64_encode(reinterpret_cast<const unsigned char *>(report_xml.c_str()), report_xml.size());
	return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
	       "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\">"
	       "<soap:Body><" +
	       prefix + "runReportResponse><" + prefix + "runReportReturn><" + prefix + "reportBytes>" + encoded + "</" +
	       prefix + "reportBytes></" + prefix + "runReportReturn></" + prefix + "runReportResponse>"
	                                                                           "</soap:Body></soap:Envelope>";
}

//! The report payload nests a second, escaped document inside <RESULT>.
std::string MakeReportXML(const std::string &escaped_rowset) {
	return "<DATA_DS><P_SQL>ignored</P_SQL><G_1><RESULT>" + escaped_rowset + "</RESULT></G_1></DATA_DS>";
}

template <typename Callable>
bool Throws(Callable &&callable) {
	try {
		callable();
	} catch (const std::exception &) {
		return true;
	}
	return false;
}

void TestEnvelopeCarriesSqlAndReportPath() {
	const auto envelope = BuildEnvelope("SELECT 1 FROM DUAL", "/Custom/Financials/RP_ARB.xdo");

	CHECK(Contains(envelope, "<![CDATA[SELECT 1 FROM DUAL]]>"));
	CHECK(Contains(envelope, "<pub:reportAbsolutePath>/Custom/Financials/RP_ARB.xdo</pub:reportAbsolutePath>"));
	CHECK(Contains(envelope, "<pub:name>p_sql</pub:name>"));
	// BI Publisher's own chunking is deliberately unused; paging rewrites the SQL.
	CHECK(Contains(envelope, "<pub:sizeOfDataChunkDownload>-1</pub:sizeOfDataChunkDownload>"));
	CHECK(Contains(envelope, "<pub:attributeFormat>xml</pub:attributeFormat>"));
}

//! "]]>" inside the SQL would otherwise end the CDATA section early and inject
//! the rest of the query into the envelope as markup.
void TestEnvelopeEscapesCdataTerminator() {
	CHECK(EscapeCdata("plain text") == "plain text");
	CHECK(EscapeCdata("a]]>b") == "a]]]]><![CDATA[>b");
	CHECK(EscapeCdata("]]>") == "]]]]><![CDATA[>");
	CHECK(EscapeCdata("]]>]]>") == "]]]]><![CDATA[>]]]]><![CDATA[>");
	// "]]" on its own is harmless and must not be touched.
	CHECK(EscapeCdata("a]]b") == "a]]b");
	CHECK(EscapeCdata("x > y") == "x > y");

	const auto envelope = BuildEnvelope("SELECT ']]>' FROM DUAL", "/r.xdo");
	// Exactly one section terminator, and it is the one that closes the value.
	size_t terminators = 0;
	for (size_t at = envelope.find("]]></pub:item>"); at != std::string::npos;
	     at = envelope.find("]]></pub:item>", at + 1)) {
		terminators++;
	}
	CHECK(terminators == 1);
	CHECK(Contains(envelope, "<![CDATA[SELECT ']]]]><![CDATA[>' FROM DUAL]]>"));
}

void TestExtractIgnoresNamespacePrefixes() {
	const auto report = MakeReportXML("&lt;ROWSET/&gt;");

	// Fusion is not consistent about which prefix it uses, so lookup is by local name.
	CHECK(ExtractReportXML(MakeSoapResponse(report, "ns2:")) == report);
	CHECK(ExtractReportXML(MakeSoapResponse(report, "")) == report);
	CHECK(ExtractReportXML(MakeSoapResponse(report, "pub:")) == report);
}

void TestExtractRejectsMalformedResponses() {
	CHECK(Throws([]() { ExtractReportXML("not xml at all <<<"); }));
	CHECK(Throws([]() { ExtractReportXML("<other:Thing/>"); }));
	CHECK(Throws(
	    []() { ExtractReportXML("<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\"/>"); }));
	// Envelope and Body present, but no reportBytes: a SOAP fault looks like this.
	CHECK(Throws([]() {
		ExtractReportXML("<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\"><soap:Body>"
		                 "<soap:Fault><soap:Reason><soap:Text>boom</soap:Text></soap:Reason></soap:Fault>"
		                 "</soap:Body></soap:Envelope>");
	}));
}

void TestParseRowsReadsNestedDocument() {
	const auto report =
	    ParseRows(MakeReportXML("&lt;ROWSET&gt;"
	                            "&lt;ROW&gt;&lt;NAME&gt;Alpha&lt;/NAME&gt;&lt;CODE&gt;A&lt;/CODE&gt;&lt;/ROW&gt;"
	                            "&lt;ROW&gt;&lt;NAME&gt;Beta&lt;/NAME&gt;&lt;CODE&gt;B&lt;/CODE&gt;&lt;/ROW&gt;"
	                            "&lt;/ROWSET&gt;"));

	CHECK(report.rows.size() == 2);
	CHECK(report.rows[0].at("NAME") == "Alpha");
	CHECK(report.rows[0].at("CODE") == "A");
	CHECK(report.rows[1].at("NAME") == "Beta");
	CHECK(report.columns.size() == 2);
}

//! Column order follows the document, which follows the SELECT list. This used
//! to come out of a std::set, so it was alphabetical and a SELECT of A, B came
//! back as B, A whenever the names sorted that way.
void TestColumnOrderFollowsTheSelectList() {
	const auto report = ParseRows(MakeReportXML("&lt;ROWSET&gt;&lt;ROW&gt;"
	                                            "&lt;ZETA&gt;z&lt;/ZETA&gt;&lt;ALPHA&gt;a&lt;/ALPHA&gt;"
	                                            "&lt;MIDDLE&gt;m&lt;/MIDDLE&gt;"
	                                            "&lt;/ROW&gt;&lt;/ROWSET&gt;"));

	CHECK(report.columns.size() == 3);
	CHECK(report.columns[0] == "ZETA");
	CHECK(report.columns[1] == "ALPHA");
	CHECK(report.columns[2] == "MIDDLE");
}

//! A column first seen on a later row still lands at the end, once.
void TestColumnListIsDeduplicatedAcrossRows() {
	const auto report =
	    ParseRows(MakeReportXML("&lt;ROWSET&gt;"
	                            "&lt;ROW&gt;&lt;A&gt;1&lt;/A&gt;&lt;/ROW&gt;"
	                            "&lt;ROW&gt;&lt;A&gt;2&lt;/A&gt;&lt;B&gt;x&lt;/B&gt;&lt;/ROW&gt;"
	                            "&lt;ROW&gt;&lt;A&gt;3&lt;/A&gt;&lt;B&gt;y&lt;/B&gt;&lt;/ROW&gt;"
	                            "&lt;/ROWSET&gt;"));

	CHECK(report.columns.size() == 2);
	CHECK(report.columns[0] == "A");
	CHECK(report.columns[1] == "B");
}

void TestParseRowsOmitsNullColumns() {
	// dbms_xmlgen drops NULL elements, so a row can simply lack a column.
	const auto report =
	    ParseRows(MakeReportXML("&lt;ROWSET&gt;"
	                            "&lt;ROW&gt;&lt;NAME&gt;Alpha&lt;/NAME&gt;&lt;CODE&gt;A&lt;/CODE&gt;&lt;/ROW&gt;"
	                            "&lt;ROW&gt;&lt;NAME&gt;Beta&lt;/NAME&gt;&lt;/ROW&gt;"
	                            "&lt;/ROWSET&gt;"));

	CHECK(report.rows.size() == 2);
	CHECK(report.rows[1].find("CODE") == report.rows[1].end());
	// The column still belongs to the schema: another row had it.
	CHECK(report.columns.size() == 2);
}

void TestParseRowsKeepsEmptyElementsDistinctFromMissingOnes() {
	const auto report =
	    ParseRows(MakeReportXML("&lt;ROWSET&gt;&lt;ROW&gt;&lt;NAME&gt;&lt;/NAME&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));

	CHECK(report.rows.size() == 1);
	// Present but empty is an empty string; absent is NULL. Not the same value.
	CHECK(report.rows[0].find("NAME") != report.rows[0].end());
	CHECK(report.rows[0].at("NAME").empty());
}

void TestParseRowsHandlesEmptyAndMultipleResults() {
	{
		const auto report = ParseRows(MakeReportXML("&lt;ROWSET/&gt;"));
		CHECK(report.rows.empty());
		CHECK(report.columns.empty());
	}
	{
		// A large report comes back as several <RESULT> elements.
		const auto report =
		    ParseRows("<DATA_DS><G_1>"
		              "<RESULT>&lt;ROWSET&gt;&lt;ROW&gt;&lt;N&gt;1&lt;/N&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;</RESULT>"
		              "<RESULT>&lt;ROWSET&gt;&lt;ROW&gt;&lt;N&gt;2&lt;/N&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;</RESULT>"
		              "</G_1></DATA_DS>");
		CHECK(report.rows.size() == 2);
		CHECK(report.rows[0].at("N") == "1");
		CHECK(report.rows[1].at("N") == "2");
		CHECK(report.columns.size() == 1);
	}
}

void TestParseRowsRejectsUnparseablePayload() {
	CHECK(Throws([]() { ParseRows("<DATA_DS><unclosed>"); }));
}

void TestExtractOracleErrors() {
	CHECK(ExtractOracleErrors("nothing to see here").empty());
	CHECK(ExtractOracleErrors("ORA-00942: table or view does not exist") ==
	      "ORA-00942: table or view does not exist");
	// Several codes in one message are all reported, in order.
	CHECK(ExtractOracleErrors("ORA-06550: line 1\nORA-00904: invalid identifier") ==
	      "ORA-06550: line 1; ORA-00904: invalid identifier");
	// "ORA-" without five digits is not a code.
	CHECK(ExtractOracleErrors("ORA-BAD: nope").empty());
}

void TestDescribeFailure() {
	// Oracle's own code wins over the SOAP wrapper around it.
	CHECK(DescribeFailure("<soap:Envelope><soap:Body><soap:Fault><faultstring>oracle.xdo.XDOException: "
	                      "ORA-00942: table or view does not exist</faultstring></soap:Fault>"
	                      "</soap:Body></soap:Envelope>") == "ORA-00942: table or view does not exist");

	// SOAP 1.1 fault with no ORA- code falls back to faultstring.
	CHECK(DescribeFailure("<soap:Envelope><soap:Body><soap:Fault>"
	                      "<faultstring>Access denied</faultstring></soap:Fault></soap:Body></soap:Envelope>") ==
	      "Access denied");

	// SOAP 1.2 puts it in Reason/Text.
	CHECK(DescribeFailure("<env:Envelope><env:Body><env:Fault><env:Reason>"
	                      "<env:Text xml:lang=\"en\">Invalid report path</env:Text>"
	                      "</env:Reason></env:Fault></env:Body></env:Envelope>") == "Invalid report path");

	// A login redirect arrives as HTML, which is the single most common failure.
	CHECK(DescribeFailure("<html><head><title>Oracle Fusion Sign In</title></head><body/></html>") ==
	      "Oracle Fusion Sign In");

	// A valid report is not a failure.
	CHECK(DescribeFailure(MakeSoapResponse(MakeReportXML("&lt;ROWSET/&gt;"))).empty());
}

void TestDescribeFailureTruncatesRunawayMessages() {
	const std::string huge = "ORA-06512: at line 1, " + std::string(8000, 'x');
	const auto described = DescribeFailure(huge);

	CHECK(!described.empty());
	CHECK(described.size() < huge.size());
	CHECK(described.size() <= ofquack::MAX_REPORTED_ERROR_LENGTH + 32);
}

// ---------------------------------------------------------------------------
// Retry policy
// ---------------------------------------------------------------------------

//! With the jitter dial at zero the delays are exactly the exponential series,
//! which is the part worth asserting; the random part is checked separately.
void TestBackoffGrowsExponentiallyAndIsCapped() {
	ofquack::RetryPolicy policy;
	policy.base_delay_ms = 1000;
	policy.multiplier = 2.0;
	policy.max_delay_ms = 30000;
	policy.jitter = 0.0;
	const auto no_jitter = []() { return 0.5; };

	CHECK(ComputeBackoffDelay(policy, 0, no_jitter) == 1000);
	CHECK(ComputeBackoffDelay(policy, 1, no_jitter) == 2000);
	CHECK(ComputeBackoffDelay(policy, 2, no_jitter) == 4000);
	// Capped, and the cap holds however far the attempt counter runs.
	CHECK(ComputeBackoffDelay(policy, 20, no_jitter) == 30000);
}

//! Jitter spreads the delay either way, so a set of clients that failed
//! together does not retry in lockstep forever.
void TestBackoffAppliesJitterBothWays() {
	ofquack::RetryPolicy policy;
	policy.base_delay_ms = 1000;
	policy.jitter = 0.2;

	CHECK(ComputeBackoffDelay(policy, 0, []() { return 0.5; }) == 1000); // centre
	CHECK(ComputeBackoffDelay(policy, 0, []() { return 0.0; }) == 800);  // -20%
	CHECK(ComputeBackoffDelay(policy, 0, []() { return 1.0; }) == 1200); // +20%
}

void TestRetryableClassification() {
	// Transient server-side failures and rate limiting are worth another go.
	CHECK(ofquack::IsRetryableStatus(500));
	CHECK(ofquack::IsRetryableStatus(503));
	CHECK(ofquack::IsRetryableStatus(429));
	CHECK(ofquack::IsRetryableStatus(408));
	// A refusal is not.
	CHECK(!ofquack::IsRetryableStatus(200));
	CHECK(!ofquack::IsRetryableStatus(401));
	CHECK(!ofquack::IsRetryableStatus(404));

	CHECK(ofquack::IsRetryableCurlError(28)); // CURLE_OPERATION_TIMEDOUT
	CHECK(ofquack::IsRetryableCurlError(7));  // CURLE_COULDNT_CONNECT
	// An unresolvable host is a configuration mistake, not a blip.
	CHECK(!ofquack::IsRetryableCurlError(6)); // CURLE_COULDNT_RESOLVE_HOST
	CHECK(!ofquack::IsRetryableCurlError(60)); // CURLE_PEER_FAILED_VERIFICATION
}

//! Retrying a statement Oracle already refused just makes the user wait three
//! times as long for the same error -- and repeating a bad password can lock
//! the account.
void TestPermanentFailuresAreNotRetried() {
	CHECK(ofquack::DescribesPermanentFailure("ORA-00942: table or view does not exist"));
	CHECK(ofquack::DescribesPermanentFailure("Authentication Failed"));
	CHECK(ofquack::DescribesPermanentFailure("invalid username or password"));
	CHECK(!ofquack::DescribesPermanentFailure("Service temporarily unavailable"));
	CHECK(!ofquack::DescribesPermanentFailure(""));
}

//! The retry loop is a free function precisely so it can be exercised here,
//! with no network and no waiting: the sleep is a parameter.
void TestRetryLoopSucceedsAfterTransientFailures() {
	ofquack::RetryPolicy policy;
	policy.max_attempts = 3;
	int calls = 0;
	std::vector<uint64_t> slept;

	const auto result = ofquack::ExecuteWithRetry(
	    policy,
	    [&]() -> std::string {
		    if (++calls < 3) {
			    throw ofquack::RetryableError("503 Service Unavailable");
		    }
		    return "ok";
	    },
	    [&](uint64_t delay) { slept.push_back(delay); }, []() { return 0.5; });

	CHECK(result == "ok");
	CHECK(calls == 3);
	// Two failures, so two waits -- and no wait before the first attempt.
	CHECK(slept.size() == 2);
	CHECK(slept[0] == 1000);
	CHECK(slept[1] == 2000);
}

void TestRetryLoopGivesUpAndSaysSo() {
	ofquack::RetryPolicy policy;
	policy.max_attempts = 3;
	int calls = 0;

	try {
		ofquack::ExecuteWithRetry(
		    policy,
		    [&]() -> std::string {
			    calls++;
			    throw ofquack::RetryableError("503 Service Unavailable");
		    },
		    [](uint64_t) {}, []() { return 0.5; });
		CHECK(false);
	} catch (const ofquack::RetryableError &error) {
		CHECK(calls == 3);
		const std::string message = error.what();
		CHECK(message.find("gave up after 3 attempts") != std::string::npos);
		// The original failure is still named, not replaced by the summary.
		CHECK(message.find("503") != std::string::npos);
	}
}

//! A statement Oracle refused, or a password it rejected, must fail on the
//! first attempt: retrying wastes time and can lock the account.
void TestRetryLoopDoesNotRetryPermanentFailures() {
	ofquack::RetryPolicy policy;
	policy.max_attempts = 5;
	int calls = 0;

	CHECK(Throws([&]() {
		ofquack::ExecuteWithRetry(
		    policy,
		    [&]() -> std::string {
			    calls++;
			    throw ofquack::AuthenticationError("wrong password");
		    },
		    [](uint64_t) {}, []() { return 0.5; });
	}));
	CHECK(calls == 1);
}

// ---------------------------------------------------------------------------
// SQL normalisation
// ---------------------------------------------------------------------------

//! The reason this is a state machine and not a regular expression: a naive
//! whitespace collapse rewrites the *data*.
void TestNormalizePreservesLiterals() {
	CHECK(ofquack::NormalizeSql("SELECT   a,   b   FROM t") == "SELECT a, b FROM t");
	// Spaces inside a literal are part of the value.
	CHECK(ofquack::NormalizeSql("SELECT 'a   b' FROM t") == "SELECT 'a   b' FROM t");
	// A doubled quote is an escaped quote, not the end of the literal.
	CHECK(ofquack::NormalizeSql("SELECT 'it''s   here' FROM t") == "SELECT 'it''s   here' FROM t");
	// Quoted identifiers keep their exact spelling.
	CHECK(ofquack::NormalizeSql("SELECT \"Odd  Name\" FROM t") == "SELECT \"Odd  Name\" FROM t");
}

void TestNormalizeStripsComments() {
	CHECK(ofquack::NormalizeSql("SELECT a -- trailing\nFROM t") == "SELECT a FROM t");
	CHECK(ofquack::NormalizeSql("SELECT a /* block */ FROM t") == "SELECT a FROM t");
	// A comment separates tokens, so removing it must not join them.
	CHECK(ofquack::NormalizeSql("SELECT a/**/FROM t") == "SELECT a FROM t");
	// Comment markers inside a literal are data.
	CHECK(ofquack::NormalizeSql("SELECT '-- not a comment' FROM t") == "SELECT '-- not a comment' FROM t");
}

//! An Oracle hint is lexically a block comment. Stripping it silently discards
//! the plan the author asked for -- the JDBC driver has exactly this bug.
void TestNormalizeKeepsOptimiserHints() {
	CHECK(ofquack::NormalizeSql("SELECT /*+ FIRST_ROWS(1000) */ a FROM t") ==
	      "SELECT /*+ FIRST_ROWS(1000) */ a FROM t");
	CHECK(ofquack::NormalizeSql("SELECT /*+ PARALLEL(4) */ a /* dropped */ FROM t") ==
	      "SELECT /*+ PARALLEL(4) */ a FROM t");
}

//! A keyword inside a literal is not a keyword, which is the distinction a
//! plain substring search misses -- and getting it wrong means silently
//! refusing to page a perfectly pageable query.
void TestFindKeywordIgnoresLiteralsAndComments() {
	CHECK(ofquack::FindKeyword("SELECT a FROM t OFFSET 5 ROWS", "OFFSET") != std::string::npos);
	CHECK(ofquack::FindKeyword("SELECT 'OFFSET' FROM t", "OFFSET") == std::string::npos);
	CHECK(ofquack::FindKeyword("SELECT a FROM t -- OFFSET\n", "OFFSET") == std::string::npos);
	CHECK(ofquack::FindKeyword("SELECT \"OFFSET\" FROM t", "OFFSET") == std::string::npos);
	// Case insensitive, and only on word boundaries.
	CHECK(ofquack::FindKeyword("select a from t offset 5 rows", "OFFSET") != std::string::npos);
	CHECK(ofquack::FindKeyword("SELECT offsets FROM t", "OFFSET") == std::string::npos);
	CHECK(ofquack::FindKeyword("SELECT a FROM my_offset", "OFFSET") == std::string::npos);
}

void TestIsSelectStatement() {
	CHECK(ofquack::IsSelectStatement("SELECT 1 FROM DUAL"));
	CHECK(ofquack::IsSelectStatement("  \n  select 1 from dual"));
	CHECK(ofquack::IsSelectStatement("/* lead */ SELECT 1 FROM DUAL"));
	CHECK(ofquack::IsSelectStatement("WITH x AS (SELECT 1 FROM DUAL) SELECT * FROM x"));
	CHECK(ofquack::IsSelectStatement("(SELECT 1 FROM DUAL)"));
	CHECK(!ofquack::IsSelectStatement("BEGIN NULL; END;"));
	CHECK(!ofquack::IsSelectStatement("UPDATE t SET a = 1"));
	CHECK(!ofquack::IsSelectStatement("SELECTED FROM t"));
}

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------

void TestPaginationClassification() {
	using ofquack::ClassifyForPagination;
	using ofquack::PaginationVerdict;

	CHECK(ClassifyForPagination("SELECT a FROM t", 500) == PaginationVerdict::YES);
	CHECK(ClassifyForPagination("SELECT a FROM t", 0) == PaginationVerdict::DISABLED);
	CHECK(ClassifyForPagination("BEGIN NULL; END;", 500) == PaginationVerdict::NOT_A_SELECT);

	// The author already limited the result; wrapping ours around theirs would
	// change which rows come back, so their intent wins.
	CHECK(ClassifyForPagination("SELECT a FROM t OFFSET 10 ROWS", 500) == PaginationVerdict::ALREADY_LIMITED);
	CHECK(ClassifyForPagination("SELECT a FROM t FETCH FIRST 10 ROWS ONLY", 500) ==
	      PaginationVerdict::ALREADY_LIMITED);

	// ROWNUM is assigned before ORDER BY and does not compose with OFFSET.
	CHECK(ClassifyForPagination("SELECT a FROM t WHERE ROWNUM < 10", 500) == PaginationVerdict::USES_ROWNUM);

	// ...but only when they are really keywords.
	CHECK(ClassifyForPagination("SELECT 'OFFSET' FROM t", 500) == PaginationVerdict::YES);
	CHECK(ClassifyForPagination("SELECT a FROM t WHERE note = 'ROWNUM'", 500) == PaginationVerdict::YES);
}

void TestApplyPagination() {
	CHECK(ofquack::ApplyPagination("SELECT a FROM t", 0, 500) ==
	      "SELECT a FROM t OFFSET 0 ROWS FETCH NEXT 500 ROWS ONLY");
	CHECK(ofquack::ApplyPagination("SELECT a FROM t", 1000, 500) ==
	      "SELECT a FROM t OFFSET 1000 ROWS FETCH NEXT 500 ROWS ONLY");
	// A trailing semicolon would land in the middle of the rewritten text.
	CHECK(ofquack::ApplyPagination("SELECT a FROM t;", 0, 10) ==
	      "SELECT a FROM t OFFSET 0 ROWS FETCH NEXT 10 ROWS ONLY");
}

// ---------------------------------------------------------------------------
// Type inference
// ---------------------------------------------------------------------------

void TestTypeInference() {
	using ofquack::InferColumnType;
	using ofquack::InferredType;

	CHECK(InferColumnType({"1", "2", "-3"}).type == InferredType::INTEGER);
	CHECK(InferColumnType({"999999999"}).type == InferredType::INTEGER);   // 9 digits
	CHECK(InferColumnType({"1000000000"}).type == InferredType::BIGINT);   // 10 digits
	CHECK(InferColumnType({"123456789012345678"}).type == InferredType::BIGINT);
	// Wider than BIGINT: falls back to DECIMAL rather than overflowing.
	CHECK(InferColumnType({"1234567890123456789012"}).type == InferredType::DECIMAL);

	const auto decimal = InferColumnType({"1.5", "2.25"});
	CHECK(decimal.type == InferredType::DECIMAL);
	CHECK(decimal.scale == 2); // widest scale seen

	CHECK(InferColumnType({"2024-01-31"}).type == InferredType::DATE);
	CHECK(InferColumnType({"2024-01-31 12:00:00"}).type == InferredType::TIMESTAMP);
	CHECK(InferColumnType({"2024-01-31T12:00:00"}).type == InferredType::TIMESTAMP);
	CHECK(InferColumnType({"2024-01-31T12:00:00.123"}).type == InferredType::TIMESTAMP);

	CHECK(InferColumnType({"hello"}).type == InferredType::VARCHAR);
	// One value that does not fit drops the whole column: half a column of
	// NULLs is worse than a column of strings.
	CHECK(InferColumnType({"1", "2", "not a number"}).type == InferredType::VARCHAR);
	CHECK(InferColumnType({"2024-01-31", "31/01/2024"}).type == InferredType::VARCHAR);
	// Mixed integers and decimals are all numbers.
	CHECK(InferColumnType({"1", "2.5"}).type == InferredType::DECIMAL);
}

//! '00123' is an account code, and reading it as 123 loses information the
//! user cannot get back.
void TestTypeInferenceKeepsLeadingZeros() {
	using ofquack::InferColumnType;
	using ofquack::InferredType;

	CHECK(InferColumnType({"00123"}).type == InferredType::VARCHAR);
	CHECK(InferColumnType({"1", "2", "007"}).type == InferredType::VARCHAR);
	// A plain zero is still a number.
	CHECK(InferColumnType({"0", "1"}).type == InferredType::INTEGER);
	CHECK(InferColumnType({"0.50"}).type == InferredType::DECIMAL);
}

void TestTypeInferenceWithEmptyValues() {
	using ofquack::InferColumnType;
	using ofquack::InferredType;

	// Empty values fit any type and are skipped.
	CHECK(InferColumnType({"", "42", ""}).type == InferredType::INTEGER);
	// A column of nothing but empties has no evidence at all.
	CHECK(InferColumnType({"", "", ""}).type == InferredType::VARCHAR);
	CHECK(InferColumnType({}).type == InferredType::VARCHAR);
}

// ---------------------------------------------------------------------------
// Secured views
// ---------------------------------------------------------------------------

//! The JDBC driver lists twelve pairs but only eleven take effect, because
//! HR_ALL_ORGANIZATION_UNITS_F appears twice and its map keeps the last. That
//! resolution is pinned here rather than left to map ordering, which C++ does
//! not guarantee -- otherwise the same query could hit different views on
//! different platforms.
void TestSecuredViewMappings() {
	const auto &mappings = ofquack::SecuredViewMappings();
	CHECK(mappings.size() == 11);

	bool found_org_units = false;
	for (const auto &mapping : mappings) {
		if (mapping.first == "HR_ALL_ORGANIZATION_UNITS_F") {
			CHECK(!found_org_units); // exactly once
			found_org_units = true;
			CHECK(mapping.second == "PER_LEGAL_EMPL_SECURED_LIST_V");
		}
	}
	CHECK(found_org_units);
}

void TestApplySecuredViews() {
	CHECK(ofquack::ApplySecuredViews("SELECT * FROM PER_ALL_PEOPLE_F") ==
	      "SELECT * FROM PER_PERSON_SECURED_LIST_V");
	// Case insensitive.
	CHECK(ofquack::ApplySecuredViews("select * from per_all_people_f") ==
	      "select * from PER_PERSON_SECURED_LIST_V");
	// Untouched when nothing matches.
	CHECK(ofquack::ApplySecuredViews("SELECT * FROM GL_JE_HEADERS") == "SELECT * FROM GL_JE_HEADERS");
	// Word boundaries: a longer name that merely contains one is not a match.
	CHECK(ofquack::ApplySecuredViews("SELECT * FROM PER_LOCATIONS_X") == "SELECT * FROM PER_LOCATIONS_X");
	// A value that happens to spell a table name is data, not a table.
	CHECK(ofquack::ApplySecuredViews("SELECT * FROM t WHERE note = 'PER_PERSONS'") ==
	      "SELECT * FROM t WHERE note = 'PER_PERSONS'");
}

// ---------------------------------------------------------------------------
// Dictionary queries and type mapping
// ---------------------------------------------------------------------------

void TestMetadataQueriesUseFusionDictionary() {
	const auto tables = ofquack::metadata::TablesByTypes({"TABLE", "VIEW"});
	// FND_VIEWS and FND_TABLES, not ALL_TABLES: only Fusion's own dictionary
	// carries TABLE_ID, and TABLE_ID is how columns are found.
	CHECK(Contains(tables, "FROM FND_VIEWS"));
	CHECK(Contains(tables, "FROM FND_TABLES"));
	CHECK(Contains(tables, "t.table_id AS TABLE_ID"));
	CHECK(Contains(tables, "'TABLE','VIEW'"));

	const auto columns = ofquack::metadata::ColumnsByTableIds({"101", "102"});
	CHECK(Contains(columns, "FROM FND_COLUMNS c"));
	CHECK(Contains(columns, "JOIN FND_TABLES t ON c.table_id = t.table_id"));
	CHECK(Contains(columns, "IN (101,102)"));

	// Views are not in FND_COLUMNS at all.
	CHECK(Contains(ofquack::metadata::ColumnsOfViews("GL_%_V"), "FROM all_tab_columns"));
	CHECK(Contains(ofquack::metadata::PrimaryKeys("T"), "constraint_type = 'P'"));
	CHECK(Contains(ofquack::metadata::ForeignKeys("T"), "constraint_type = 'R'"));
	// The predicate, not the CASE in the select list, which is always there.
	CHECK(Contains(ofquack::metadata::Indexes("T", true), "AND idx.uniqueness = 'UNIQUE'"));
	CHECK(!Contains(ofquack::metadata::Indexes("T", false), "AND idx.uniqueness = 'UNIQUE'"));
}

//! These statements are built by concatenation, and the JDBC driver interpolates
//! names into them raw -- so an apostrophe in a name breaks the statement, and
//! could carry more than a name.
void TestMetadataQueriesEscapeLiterals() {
	CHECK(ofquack::metadata::QuoteLiteral("O'Brien") == "O''Brien");
	const auto sql = ofquack::metadata::PrimaryKeys("T' OR '1'='1");
	CHECK(Contains(sql, "T'' OR ''1''=''1"));

	// A non-numeric TABLE_ID never reaches the statement.
	const auto columns = ofquack::metadata::ColumnsByTableIds({"1", "2); DROP TABLE x--", "3"});
	CHECK(Contains(columns, "IN (1,3)"));
	CHECK(!Contains(columns, "DROP TABLE"));
}

void TestOffsetPagination() {
	// The row-limiting clause is appended after ORDER BY, not wrapped around
	// the statement. A ROWNUM wrapper makes the inner query produce offset+n
	// rows and discard the first offset of them; once that inner count passes
	// the report's own row limit the server truncates it, the outer filter
	// finds nothing, and the listing looks finished. That stopped a
	// 27,000-table dictionary at 4,000 on a real instance.
	const auto first = ofquack::metadata::PaginateByOffset("SELECT a FROM t ORDER BY a", 0, 400);
	CHECK(first == "SELECT a FROM t ORDER BY a OFFSET 0 ROWS FETCH NEXT 400 ROWS ONLY");
	CHECK(!Contains(first, "ROWNUM"));

	const auto deep = ofquack::metadata::PaginateByOffset("SELECT a FROM t ORDER BY a", 26000, 400);
	CHECK(Contains(deep, "OFFSET 26000 ROWS FETCH NEXT 400 ROWS ONLY"));
}

//! The dictionary aliases are shifted by one: the column labelled
//! DECIMAL_DIGITS carries the precision. The fetcher un-shifts them, so this
//! mapper takes precision and scale in their true meaning.
void TestOracleTypeMapping() {
	using ofquack::InferredType;
	using ofquack::MapOracleType;

	CHECK(MapOracleType("VARCHAR2", 0, 0).type == InferredType::VARCHAR);
	CHECK(MapOracleType("CLOB", 0, 0).type == InferredType::VARCHAR);
	// FND's single-letter domain codes.
	CHECK(MapOracleType("V", 0, 0).type == InferredType::VARCHAR);

	CHECK(MapOracleType("NUMBER", 9, 0).type == InferredType::INTEGER);
	CHECK(MapOracleType("NUMBER", 10, 0).type == InferredType::BIGINT);
	CHECK(MapOracleType("NUMBER", 18, 0).type == InferredType::BIGINT);
	// Too wide for BIGINT, or fractional.
	CHECK(MapOracleType("NUMBER", 19, 0).type == InferredType::DECIMAL);
	const auto money = MapOracleType("NUMBER", 12, 2);
	CHECK(money.type == InferredType::DECIMAL);
	CHECK(money.scale == 2);
	// NUMBER with nothing declared: the widest thing it could be.
	CHECK(MapOracleType("NUMBER", 0, 0).type == InferredType::DECIMAL);

	// Oracle's DATE carries a time of day, so DATE would truncate it.
	CHECK(MapOracleType("DATE", 0, 0).type == InferredType::TIMESTAMP);
	CHECK(MapOracleType("TIMESTAMP(6)", 0, 0).type == InferredType::TIMESTAMP);

	// Unrecognised: the caller falls back to inference rather than guessing.
	CHECK(!MapOracleType("RAW", 0, 0).known);
	CHECK(!MapOracleType("BLOB", 0, 0).known);
	CHECK(!MapOracleType("", 0, 0).known);
}

// ---------------------------------------------------------------------------
// SSO: JWT, token cache, WebSocket framing, JSON
// ---------------------------------------------------------------------------

//! Builds a JWT with the given payload. The signature is nonsense on purpose:
//! nothing here verifies it, and nothing should -- Fusion authenticates the
//! token when it is used, and this only wants to know when to ask for another.
std::string MakeJwt(const std::string &payload_json) {
	const auto encode = [](const std::string &text) {
		auto encoded = base64_encode(reinterpret_cast<const unsigned char *>(text.c_str()), text.size(), true);
		while (!encoded.empty() && encoded.back() == '=') {
			encoded.pop_back();
		}
		return encoded;
	};
	return encode("{\"alg\":\"RS256\"}") + "." + encode(payload_json) + ".not-a-real-signature";
}

void TestJwtClaims() {
	const auto claims = ofquack::ParseJwtClaims(MakeJwt("{\"sub\":\"analyst@example.com\",\"exp\":1893456000}"));
	CHECK(claims.parsed);
	CHECK(claims.expires_at_epoch == 1893456000);
	CHECK(claims.subject == "analyst@example.com");

	// A token without exp still parses; the cache falls back to a fixed life.
	const auto no_expiry = ofquack::ParseJwtClaims(MakeJwt("{\"sub\":\"x\"}"));
	CHECK(no_expiry.parsed);
	CHECK(no_expiry.expires_at_epoch == 0);

	// Not a JWT at all.
	CHECK(!ofquack::ParseJwtClaims("").parsed);
	CHECK(!ofquack::ParseJwtClaims("not.a.jwt").parsed);
	CHECK(!ofquack::ParseJwtClaims("onlyonepart").parsed);
}

void TestBase64UrlDecoding() {
	// base64url swaps two characters and drops the padding.
	CHECK(ofquack::DecodeBase64Url("YQ") == "a");
	CHECK(ofquack::DecodeBase64Url("YWJj") == "abc");
	// '-' and '_' stand in for '+' and '/'.
	CHECK(ofquack::DecodeBase64Url("--__").size() == 3);
}

void TestTokenCacheExpiryAndRefresh() {
	int64_t now = 1000000;
	ofquack::TokenCache::SetClockForTesting([&now]() { return now; });
	ofquack::TokenCache::Get().Clear();
	auto &cache = ofquack::TokenCache::Get();

	// exp one hour out; the cache holds it back by the safety buffer.
	cache.Store("host", MakeJwt("{\"sub\":\"a\",\"exp\":" + std::to_string(now + 3600) + "}"), "refresh", 0);
	auto token = cache.Lookup("host");
	CHECK(token.Valid());
	CHECK(token.subject == "a");
	CHECK(token.expires_at_epoch == now + 3600 - ofquack::TOKEN_EXPIRY_BUFFER_SECONDS);

	// Fresh: no reason to refresh yet.
	CHECK(!cache.ShouldRefresh("host"));

	// Past 80% of its life, a refresh is due -- between queries, rather than in
	// the middle of one.
	now += static_cast<int64_t>((3600 - ofquack::TOKEN_EXPIRY_BUFFER_SECONDS) * 0.85);
	CHECK(cache.ShouldRefresh("host"));

	// Past the (buffered) expiry it is gone entirely.
	now += 3600;
	CHECK(!cache.Lookup("host").Valid());

	ofquack::TokenCache::Get().Clear();
	ofquack::TokenCache::SetClockForTesting(nullptr);
}

void TestTokenCacheFallbackLifetime() {
	int64_t now = 500000;
	ofquack::TokenCache::SetClockForTesting([&now]() { return now; });
	ofquack::TokenCache::Get().Clear();
	auto &cache = ofquack::TokenCache::Get();

	// No exp and no expires_in: a fixed lifetime rather than treating it as
	// eternal, which would mean discovering the expiry as a failed query.
	cache.Store("host", "not-a-jwt", "", 0);
	auto token = cache.Lookup("host");
	CHECK(token.Valid());
	CHECK(token.expires_at_epoch ==
	      now + ofquack::FALLBACK_TOKEN_LIFETIME_SECONDS - ofquack::TOKEN_EXPIRY_BUFFER_SECONDS);

	// expires_in is used when the token says nothing itself. Note the safety
	// margin is capped at half the life: a two-minute token would otherwise be
	// discarded on arrival, since the full margin exceeds it.
	cache.Store("other", "not-a-jwt", "", 120);
	auto short_token = cache.Lookup("other");
	CHECK(short_token.Valid());
	CHECK(short_token.expires_at_epoch == now + 60);

	// Tokens are per host: signing in to one instance is not signing in to another.
	CHECK(!cache.Lookup("third").Valid());

	ofquack::TokenCache::Get().Clear();
	ofquack::TokenCache::SetClockForTesting(nullptr);
}

void TestWebSocketUrlParsing() {
	std::string host;
	uint16_t port = 0;
	std::string path;

	CHECK(ofquack::ParseWebSocketUrl("ws://127.0.0.1:9222/devtools/page/ABC", host, port, path));
	CHECK(host == "127.0.0.1");
	CHECK(port == 9222);
	CHECK(path == "/devtools/page/ABC");

	CHECK(ofquack::ParseWebSocketUrl("ws://127.0.0.1/x", host, port, path));
	CHECK(port == 80);

	// Only ws:// -- the debugging port is plain HTTP on loopback.
	CHECK(!ofquack::ParseWebSocketUrl("wss://example.com/x", host, port, path));
	CHECK(!ofquack::ParseWebSocketUrl("http://127.0.0.1:9222/x", host, port, path));
}

//! The handshake value from RFC 6455's own example, so this checks the SHA-1
//! and base64 wiring against a published vector rather than against itself.
void TestWebSocketAcceptKey() {
	CHECK(ofquack::ComputeWebSocketAccept("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

void TestJsonFieldReading() {
	const std::string document = R"({"id":7,"result":{"value":{"status":"success","token":"abc.def","expiresIn":3600}}})";

	CHECK(ofquack::json::StringField(document, "status") == "success");
	CHECK(ofquack::json::StringField(document, "token") == "abc.def");
	CHECK(ofquack::json::IntegerField(document, "expiresIn") == 3600);
	CHECK(ofquack::json::IntegerField(document, "id") == 7);
	CHECK(ofquack::json::StringField(document, "missing").empty());
	// A number is not a string, and vice versa.
	CHECK(ofquack::json::StringField(document, "expiresIn").empty());
	CHECK(ofquack::json::IntegerField(document, "status") == 0);

	// Escapes are undone.
	CHECK(ofquack::json::StringField(R"({"a":"line\nbreak"})", "a") == "line\nbreak");
	CHECK(ofquack::json::StringField(R"({"a":"quote\"inside"})", "a") == "quote\"inside");
}

void TestJsonArraySplitting() {
	const std::string targets = R"([{"type":"page","webSocketDebuggerUrl":"ws://127.0.0.1:9222/a"},)"
	                            R"({"type":"background_page","webSocketDebuggerUrl":"ws://127.0.0.1:9222/b"}])";
	const auto elements = ofquack::json::ParseArray(targets);
	CHECK(elements.size() == 2);
	CHECK(ofquack::json::StringField(elements[0], "type") == "page");
	CHECK(ofquack::json::StringField(elements[1], "type") == "background_page");

	CHECK(ofquack::json::ParseArray("[]").empty());
	CHECK(ofquack::json::ParseArray("not json").empty());
}

void TestJsonQuoting() {
	CHECK(ofquack::json::QuoteString("plain") == "\"plain\"");
	CHECK(ofquack::json::QuoteString("say \"hi\"") == "\"say \\\"hi\\\"\"");
	CHECK(ofquack::json::QuoteString("a\nb") == "\"a\\nb\"");
	CHECK(ofquack::json::QuoteString("back\\slash") == "\"back\\\\slash\"");
}

//! The BI Publisher service is at the same path on every Fusion instance, so
//! naming the host is enough; requiring the whole URL asks the user to repeat
//! a constant, and getting it slightly wrong sends the request to the
//! application, which answers with its home page.
void TestEndpointNormalisation() {
	using ofquack::NormalizeFusionEndpoint;
	const std::string SERVICE = "/xmlpserver/services/ExternalReportWSSService?WSDL";

	CHECK(NormalizeFusionEndpoint("https://fa.example.com") == "https://fa.example.com" + SERVICE);
	CHECK(NormalizeFusionEndpoint("https://fa.example.com/") == "https://fa.example.com" + SERVICE);
	// A missing scheme is assumed to be https, not http.
	CHECK(NormalizeFusionEndpoint("fa.example.com") == "https://fa.example.com" + SERVICE);
	CHECK(NormalizeFusionEndpoint("  https://fa.example.com  ") == "https://fa.example.com" + SERVICE);
	CHECK(NormalizeFusionEndpoint("https://fa.example.com:443") == "https://fa.example.com:443" + SERVICE);

	// An endpoint that already carries a path was written deliberately.
	const auto full = "https://fa.example.com" + SERVICE;
	CHECK(NormalizeFusionEndpoint(full) == full);
	CHECK(NormalizeFusionEndpoint("https://proxy.example.com/fusion/xmlpserver/services/X?WSDL") ==
	      "https://proxy.example.com/fusion/xmlpserver/services/X?WSDL");

	CHECK(NormalizeFusionEndpoint("").empty());
	CHECK(NormalizeFusionEndpoint("   ").empty());
}

//! sso_login_url is optional: the report endpoint and the application share a
//! host, and reaching the application unauthenticated is what triggers the
//! sign-on redirect. Asking for it again would be asking twice for one fact.
void TestDefaultLoginUrl() {
	CHECK(ofquack::DefaultLoginUrl("https://fa.example.com/xmlpserver/services/X?WSDL") == "https://fa.example.com");
	CHECK(ofquack::DefaultLoginUrl("https://fa.example.com:443/x") == "https://fa.example.com:443");
	// An endpoint with no scheme still yields something openable.
	CHECK(ofquack::DefaultLoginUrl("fa.example.com/x") == "https://fa.example.com");
	// Credentials in the authority must not be handed to the browser.
	CHECK(ofquack::DefaultLoginUrl("https://user:pass@fa.example.com/x") == "https://fa.example.com");
	CHECK(ofquack::DefaultLoginUrl("").empty());
}

//! The script is what actually collects the token, so the endpoints it calls
//! are worth pinning: they are the whole integration contract with Fusion.
void TestTokenCollectionScript() {
	const std::string script = ofquack::TokenCollectionScript();
	CHECK(Contains(script, "/fscmRestApi/anticsrf"));
	CHECK(Contains(script, "/fscmRestApi/tokenrelay"));
	// tokenrelay refuses a request without the anti-CSRF header, which is what
	// stops another site from collecting a token this way.
	CHECK(Contains(script, "X-XSRF-TOKEN"));
	CHECK(Contains(script, "same-origin"));
	// It reports rather than throws while the user is still signing in.
	CHECK(Contains(script, "waiting"));

	// It must survive being embedded in a JSON message to Chrome.
	const auto quoted = ofquack::json::QuoteString(script);
	CHECK(quoted.front() == '"');
	CHECK(quoted.back() == '"');
}

// ---------------------------------------------------------------------------
// Circuit breaker
// ---------------------------------------------------------------------------

//! A fake clock, so the suite can cross the recovery window without sleeping.
struct TestClock {
	std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();

	std::function<std::chrono::steady_clock::time_point()> Fn() {
		return [this]() { return now; };
	}
	void Advance(int64_t ms) {
		now += std::chrono::milliseconds(ms);
	}
};

void TestBreakerOpensAfterConsecutiveFailures() {
	ofquack::CircuitBreaker breaker(ofquack::CircuitBreakerSettings {3, 60000});
	TestClock clock;
	breaker.SetClockForTesting(clock.Fn());

	breaker.RequireClosed("host"); // fine while closed
	breaker.RecordFailure();
	breaker.RecordFailure();
	breaker.RequireClosed("host"); // still under the threshold
	breaker.RecordFailure();

	CHECK(breaker.CurrentState() == ofquack::CircuitBreaker::State::OPEN);
	CHECK(Throws([&]() { breaker.RequireClosed("host"); }));
}

//! One success is enough to forget the earlier failures: they have to be
//! consecutive, otherwise a long-lived connection trips on unrelated blips.
void TestBreakerResetsOnSuccess() {
	ofquack::CircuitBreaker breaker(ofquack::CircuitBreakerSettings {3, 60000});
	TestClock clock;
	breaker.SetClockForTesting(clock.Fn());

	breaker.RecordFailure();
	breaker.RecordFailure();
	breaker.RecordSuccess();
	breaker.RecordFailure();
	breaker.RecordFailure();

	CHECK(breaker.CurrentState() == ofquack::CircuitBreaker::State::CLOSED);
}

void TestBreakerProbesAfterRecoveryWindow() {
	ofquack::CircuitBreaker breaker(ofquack::CircuitBreakerSettings {1, 60000});
	TestClock clock;
	breaker.SetClockForTesting(clock.Fn());

	breaker.RecordFailure();
	CHECK(Throws([&]() { breaker.RequireClosed("host"); }));

	clock.Advance(59000);
	CHECK(Throws([&]() { breaker.RequireClosed("host"); }));

	// Window passed: one probe is let through.
	clock.Advance(2000);
	breaker.RequireClosed("host");
	CHECK(breaker.CurrentState() == ofquack::CircuitBreaker::State::HALF_OPEN);

	// The probe failed, so the wait starts again rather than admitting a flood.
	breaker.RecordFailure();
	CHECK(breaker.CurrentState() == ofquack::CircuitBreaker::State::OPEN);
	CHECK(Throws([&]() { breaker.RequireClosed("host"); }));

	// A successful probe closes it.
	clock.Advance(61000);
	breaker.RequireClosed("host");
	breaker.RecordSuccess();
	CHECK(breaker.CurrentState() == ofquack::CircuitBreaker::State::CLOSED);
}

//! The error names the host and says how long the wait is, since "circuit open"
//! on its own tells an analyst nothing actionable.
void TestBreakerErrorIsInformative() {
	ofquack::CircuitBreaker breaker(ofquack::CircuitBreakerSettings {1, 60000});
	breaker.RecordFailure();
	try {
		breaker.RequireClosed("fusion.example.com");
		CHECK(false);
	} catch (const ofquack::CircuitOpenError &error) {
		const std::string message = error.what();
		CHECK(message.find("fusion.example.com") != std::string::npos);
		CHECK(message.find("not attempted") != std::string::npos);
	}
}

// ---------------------------------------------------------------------------
// Host keys
// ---------------------------------------------------------------------------

//! Two spellings of one instance must map to one throttle, or the limit that
//! protects the server silently doubles.
void TestHostOf() {
	CHECK(ofquack::HostOf("https://fusion.example.com/xmlpserver/services/X?WSDL") == "fusion.example.com");
	CHECK(ofquack::HostOf("http://fusion.example.com") == "fusion.example.com");
	CHECK(ofquack::HostOf("https://fusion.example.com:443/path") == "fusion.example.com:443");
	// Credentials in the authority would otherwise leak into error messages.
	CHECK(ofquack::HostOf("https://user:pass@fusion.example.com/x") == "fusion.example.com");
}

//! The throttle bounds concurrency rather than rate: the slot is held for the
//! whole request, so a second caller waits for the first to finish.
void TestThrottleSerialisesConcurrentCallers() {
	ofquack::ResetHostStateForTesting();
	auto throttle = ofquack::ThrottleForHost("host", 1);

	std::atomic<int> concurrent {0};
	std::atomic<int> peak {0};
	std::vector<std::thread> workers;
	for (int i = 0; i < 4; i++) {
		workers.emplace_back([&]() {
			ofquack::HostThrottle::Slot slot(*throttle);
			const int now = ++concurrent;
			int seen = peak.load();
			while (now > seen && !peak.compare_exchange_weak(seen, now)) {
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(5));
			--concurrent;
		});
	}
	for (auto &worker : workers) {
		worker.join();
	}
	CHECK(peak.load() == 1);
	ofquack::ResetHostStateForTesting();
}

struct TestCase {
	const char *name;
	void (*run)();
};

const TestCase TESTS[] = {
    {"envelope carries sql and report path", TestEnvelopeCarriesSqlAndReportPath},
    {"envelope escapes cdata terminator", TestEnvelopeEscapesCdataTerminator},
    {"extract ignores namespace prefixes", TestExtractIgnoresNamespacePrefixes},
    {"extract rejects malformed responses", TestExtractRejectsMalformedResponses},
    {"parse rows reads nested document", TestParseRowsReadsNestedDocument},
    {"column order follows the select list", TestColumnOrderFollowsTheSelectList},
    {"column list is deduplicated across rows", TestColumnListIsDeduplicatedAcrossRows},
    {"parse rows omits null columns", TestParseRowsOmitsNullColumns},
    {"parse rows keeps empty elements", TestParseRowsKeepsEmptyElementsDistinctFromMissingOnes},
    {"parse rows handles empty and multiple results", TestParseRowsHandlesEmptyAndMultipleResults},
    {"parse rows rejects unparseable payload", TestParseRowsRejectsUnparseablePayload},
    {"extract oracle errors", TestExtractOracleErrors},
    {"describe failure", TestDescribeFailure},
    {"describe failure truncates runaway messages", TestDescribeFailureTruncatesRunawayMessages},
    {"backoff grows exponentially and is capped", TestBackoffGrowsExponentiallyAndIsCapped},
    {"backoff applies jitter both ways", TestBackoffAppliesJitterBothWays},
    {"retryable classification", TestRetryableClassification},
    {"permanent failures are not retried", TestPermanentFailuresAreNotRetried},
    {"retry loop succeeds after transient failures", TestRetryLoopSucceedsAfterTransientFailures},
    {"retry loop gives up and says so", TestRetryLoopGivesUpAndSaysSo},
    {"retry loop does not retry permanent failures", TestRetryLoopDoesNotRetryPermanentFailures},
    {"normalize preserves literals", TestNormalizePreservesLiterals},
    {"normalize strips comments", TestNormalizeStripsComments},
    {"normalize keeps optimiser hints", TestNormalizeKeepsOptimiserHints},
    {"find keyword ignores literals and comments", TestFindKeywordIgnoresLiteralsAndComments},
    {"is select statement", TestIsSelectStatement},
    {"pagination classification", TestPaginationClassification},
    {"apply pagination", TestApplyPagination},
    {"type inference", TestTypeInference},
    {"type inference keeps leading zeros", TestTypeInferenceKeepsLeadingZeros},
    {"type inference with empty values", TestTypeInferenceWithEmptyValues},
    {"secured view mappings", TestSecuredViewMappings},
    {"apply secured views", TestApplySecuredViews},
    {"metadata queries use fusion dictionary", TestMetadataQueriesUseFusionDictionary},
    {"metadata queries escape literals", TestMetadataQueriesEscapeLiterals},
    {"offset pagination", TestOffsetPagination},
    {"oracle type mapping", TestOracleTypeMapping},
    {"jwt claims", TestJwtClaims},
    {"base64url decoding", TestBase64UrlDecoding},
    {"token cache expiry and refresh", TestTokenCacheExpiryAndRefresh},
    {"token cache fallback lifetime", TestTokenCacheFallbackLifetime},
    {"websocket url parsing", TestWebSocketUrlParsing},
    {"websocket accept key", TestWebSocketAcceptKey},
    {"json field reading", TestJsonFieldReading},
    {"json array splitting", TestJsonArraySplitting},
    {"json quoting", TestJsonQuoting},
    {"endpoint normalisation", TestEndpointNormalisation},
    {"default login url", TestDefaultLoginUrl},
    {"token collection script", TestTokenCollectionScript},
    {"breaker opens after consecutive failures", TestBreakerOpensAfterConsecutiveFailures},
    {"breaker resets on success", TestBreakerResetsOnSuccess},
    {"breaker probes after recovery window", TestBreakerProbesAfterRecoveryWindow},
    {"breaker error is informative", TestBreakerErrorIsInformative},
    {"host of", TestHostOf},
    {"throttle serialises concurrent callers", TestThrottleSerialisesConcurrentCallers},
};

} // namespace

int main() {
	for (const auto &test : TESTS) {
		std::cout << "  " << test.name << std::endl;
		test.run();
	}
	std::cout << sizeof(TESTS) / sizeof(TESTS[0]) << " pure tests passed" << std::endl;
	return 0;
}
