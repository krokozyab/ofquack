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

void TestParseRowsSanitizesBareAmpersand() {
	// The outer document correctly escapes the ampersand, but decoding its text
	// exposes the malformed inner XML emitted by BI Publisher.
	const auto report = ParseRows(MakeReportXML("&lt;ROWSET&gt;&lt;ROW&gt;&lt;REMARKS&gt;"
	                                                "Description with &amp; character"
	                                                "&lt;/REMARKS&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));

	CHECK(report.rows.size() == 1);
	CHECK(report.rows[0].at("REMARKS") == "Description with & character");
}

void TestParseRowsPreservesValidEntities() {
	// Entities belonging to the inner document are escaped once more in the
	// outer one. A bare ampersand forces the fallback, which must not turn the
	// valid entities beside it into literal "&amp;...;" text.
	const auto report = ParseRows(MakeReportXML("&lt;ROWSET&gt;&lt;ROW&gt;&lt;VALUE&gt;"
	                                                "bare &amp; then &amp;amp;&amp;lt;&amp;gt;&amp;quot;&amp;apos;"
	                                                "&amp;#65;&amp;#x42;"
	                                                "&lt;/VALUE&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"));

	CHECK(report.rows.size() == 1);
	CHECK(report.rows[0].at("VALUE") == "bare & then &<>\"'AB");
}

//! The real one. A table described as "a dictionary of <area_id, date>
//! combinations" reaches us with the brackets unescaped, and the whole
//! 112 KB page failed to parse -- which, skipped as unparseable, is what
//! ended the dictionary listing at FFS_MSG_AGENT_CREDENTIAL.
void TestParseRowsKeepsAngleBracketsInsideValues() {
	const auto report = ParseRows(MakeReportXML(
	    "&lt;ROWSET&gt;\n"
	    " &lt;ROW&gt;\n"
	    "  &lt;TABLE_CAT xsi:nil = \"true\"/&gt;\n"
	    "  &lt;TABLE_NAME&gt;FFS_QBI_QUOTA_PAGE&lt;/TABLE_NAME&gt;\n"
	    "  &lt;REMARKS&gt;Stores a dictionary of &lt;area_id, date&gt; combinations.&lt;/REMARKS&gt;\n"
	    "  &lt;TABLE_ID&gt;21186&lt;/TABLE_ID&gt;\n"
	    " &lt;/ROW&gt;\n"
	    " &lt;ROW&gt;\n"
	    "  &lt;TABLE_NAME&gt;NEXT_ONE&lt;/TABLE_NAME&gt;\n"
	    // Something that looks exactly like markup is still data in a value.
	    "  &lt;REMARKS&gt;Use &lt;b&gt;bold&lt;/b&gt; and a &lt; b and x &lt;&lt; 2&lt;/REMARKS&gt;\n"
	    " &lt;/ROW&gt;\n"
	    "&lt;/ROWSET&gt;"));

	CHECK(!report.truncated);
	CHECK(report.rows.size() == 2);
	CHECK(report.rows[0].at("TABLE_NAME") == "FFS_QBI_QUOTA_PAGE");
	CHECK(report.rows[0].at("REMARKS") == "Stores a dictionary of <area_id, date> combinations.");
	CHECK(report.rows[0].at("TABLE_ID") == "21186");
	// The nil column is an element with no text, not a lost one.
	CHECK(report.rows[0].count("TABLE_CAT") == 1);
	CHECK(report.rows[1].at("TABLE_NAME") == "NEXT_ONE");
	CHECK(report.rows[1].at("REMARKS") == "Use <b>bold</b> and a < b and x << 2");
}

void TestParseRowsDropsInvalidControlCharacters() {
	std::string escaped = "&lt;ROWSET&gt;&lt;ROW&gt;&lt;REMARKS&gt;before";
	escaped.push_back('\x01');
	escaped += "after&lt;/REMARKS&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;";
	const auto report = ParseRows(MakeReportXML(escaped));

	CHECK(report.rows.size() == 1);
	CHECK(report.rows[0].at("REMARKS") == "beforeafter");
}

//! The report has a limit on how much one response carries, and when it is
//! reached the block just stops mid-element. That is what stopped the table
//! listing partway through the alphabet: the block failed to parse, was
//! skipped, the page looked empty, and empty meant the end. The rows before
//! the cut are intact and are what the next page should continue from.
void TestTruncatedBlockKeepsTheCompleteRows() {
	// dbms_xmlgen pretty-prints, so the cut lands inside an element on its own
	// line, as it does on a real instance.
	const auto report = ParseRows(MakeReportXML("&lt;ROWSET&gt;\n"
	                                            " &lt;ROW&gt;\n  &lt;N&gt;1&lt;/N&gt;\n  &lt;S&gt;a&lt;/S&gt;\n &lt;/ROW&gt;\n"
	                                            " &lt;ROW&gt;\n  &lt;N&gt;2&lt;/N&gt;\n  &lt;S&gt;b&lt;/S&gt;\n &lt;/ROW&gt;\n"
	                                            " &lt;ROW&gt;\n  &lt;N&gt;3&lt;/N&gt;\n  &lt;S&gt;long description that was cu"));

	CHECK(report.truncated);
	CHECK(report.truncated_at_bytes > 0);
	CHECK(report.rows.size() == 2);
	CHECK(report.rows[0].at("N") == "1");
	CHECK(report.rows[1].at("S") == "b");
	// Column order still comes from the rows that did arrive.
	CHECK(report.columns.size() == 2);

	// A block that parses is not truncated, whatever else happened to it.
	CHECK(!ParseRows(MakeReportXML("&lt;ROWSET&gt;&lt;ROW&gt;&lt;N&gt;1&lt;/N&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"))
	           .truncated);
}

//! Cut before the first row completed: nothing can be continued from, and the
//! reason -- one row too wide for the report -- is worth naming.
void TestTruncatedBeforeTheFirstRowIsReported() {
	try {
		ParseRows(MakeReportXML("&lt;ROWSET&gt;\n &lt;ROW&gt;\n  &lt;DOC&gt;enormous value that never en"));
		CHECK(false);
	} catch (const std::runtime_error &error) {
		CHECK(std::string(error.what()).find("before its first row was complete") != std::string::npos);
		CHECK(std::string(error.what()).find("bytes arrived") != std::string::npos);
	}
}

//! A damaged block used to be skipped, and the rows of the blocks that did
//! parse were handed back as the answer. There is no way for a caller to see
//! that, which makes it the one failure worth being loud about.
void TestDamagedResultBlockIsReported() {
	CHECK(Throws([]() { ParseRows("<DATA_DS><G_1><RESULT>&lt;ROWSET&gt;&lt;ROW&gt;</RESULT></G_1></DATA_DS>"); }));

	// Two blocks, the second unreadable: the rows of the first must not be
	// passed off as the whole result.
	CHECK(Throws([]() {
		ParseRows("<DATA_DS><G_1>"
		          "<RESULT>&lt;ROWSET&gt;&lt;ROW&gt;&lt;N&gt;1&lt;/N&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;</RESULT>"
		          "<RESULT>&lt;ROWSET&gt;&lt;ROW&gt;</RESULT>"
		          "</G_1></DATA_DS>");
	}));

	// An empty block is a result set with no rows, which is an answer.
	const auto empty = ParseRows("<DATA_DS><G_1><RESULT></RESULT></G_1></DATA_DS>");
	CHECK(empty.rows.empty());
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

//! OFFSET/FETCH only partitions a result the server has ordered, so knowing
//! whether the author supplied an order decides whether one has to be added.
void TestOrderByDetection() {
	using ofquack::HasOrderBy;

	CHECK(!HasOrderBy("SELECT a FROM t"));
	CHECK(HasOrderBy("SELECT a FROM t ORDER BY a"));
	CHECK(HasOrderBy("SELECT a FROM t ORDER BY a DESC, b"));

	// A literal is data, not a clause.
	CHECK(!HasOrderBy("SELECT 'ORDER BY' FROM t"));
	// ORDER is a column name often enough, and BY belongs to other clauses.
	CHECK(!HasOrderBy("SELECT \"ORDER\" FROM t"));
	CHECK(!HasOrderBy("SELECT a, count(*) FROM t GROUP BY a"));
	// Both present, in that order: the ORDER BY is still there.
	CHECK(HasOrderBy("SELECT a, count(*) FROM t GROUP BY a ORDER BY a"));
	// ORDER without a BY after it is not the clause.
	CHECK(!HasOrderBy("SELECT ORDER FROM t WHERE x = 1"));
}

void TestOrderingRewrites() {
	using ofquack::AppendOrderByPositions;
	using ofquack::WrapWithOrderBy;

	CHECK(AppendOrderByPositions("SELECT a, b FROM t", {1, 2}) == "SELECT a, b FROM t ORDER BY 1, 2");
	// A trailing semicolon would land in the middle of the rewrite.
	CHECK(AppendOrderByPositions("SELECT a FROM t;", {1}) == "SELECT a FROM t ORDER BY 1");
	// Nothing sortable to order by: the statement is left as it is rather than
	// given an empty clause.
	CHECK(AppendOrderByPositions("SELECT a FROM t", {}) == "SELECT a FROM t");
	// Positions may skip a column, which is what keeps a CLOB out of the order.
	CHECK(AppendOrderByPositions("SELECT a, doc, b FROM t", {1, 3}) == "SELECT a, doc, b FROM t ORDER BY 1, 3");

	// Wrapped rather than appended to: appending would attach the clause to the
	// last branch of a UNION rather than to the result as a whole.
	CHECK(WrapWithOrderBy("SELECT a FROM t UNION ALL SELECT a FROM u", 1) ==
	      "SELECT * FROM (SELECT a FROM t UNION ALL SELECT a FROM u) ORDER BY 1");
	CHECK(WrapWithOrderBy("SELECT a, b, c FROM t", 3) == "SELECT * FROM (SELECT a, b, c FROM t) ORDER BY 1, 2, 3");
}

//! The probe that asks whether Oracle will order by a set of columns must
//! not make it do any work: one row, taken before the ORDER BY applies.
void TestOrderProbe() {
	CHECK(ofquack::OrderProbe("SELECT a, doc, b FROM t", {1, 3}) ==
	      "SELECT * FROM (SELECT * FROM (SELECT a, doc, b FROM t) WHERE ROWNUM <= 1) ORDER BY 1, 3");
	CHECK(ofquack::WrapWithOrderByPositions("SELECT a, doc, b FROM t", {1, 3}) ==
	      "SELECT * FROM (SELECT a, doc, b FROM t) ORDER BY 1, 3");
}

//! A seek writes the last row's key back into the next statement. The report
//! hands every value over as text; the literal has to say what the text is
//! in a way no session setting can reinterpret.
void TestKeyLiterals() {
	using ofquack::KeyKind;
	using ofquack::KeyLiteral;

	CHECK(KeyLiteral(KeyKind::NUMBER, "42") == "42");
	CHECK(KeyLiteral(KeyKind::NUMBER, "-1.5") == "-1.5");
	CHECK(KeyLiteral(KeyKind::NUMBER, "") == "");
	CHECK(KeyLiteral(KeyKind::NUMBER, "12abc") == "");
	CHECK(KeyLiteral(KeyKind::NUMBER, "1.2.3") == "");

	CHECK(KeyLiteral(KeyKind::TEXT, "INV-001") == "'INV-001'");
	CHECK(KeyLiteral(KeyKind::TEXT, "O'Brien") == "'O''Brien'");
	// Oracle stores '' as NULL, and nothing sorts after NULL.
	CHECK(KeyLiteral(KeyKind::TEXT, "") == "");

	// dbms_xmlgen writes dates in ISO 8601 with a T; the format model is spelt
	// out so NLS_DATE_FORMAT has no say.
	CHECK(KeyLiteral(KeyKind::DATE, "2024-01-31") == "TO_DATE('2024-01-31', 'YYYY-MM-DD')");
	CHECK(KeyLiteral(KeyKind::DATE, "2024-01-31T10:20:30") ==
	      "TO_DATE('2024-01-31 10:20:30', 'YYYY-MM-DD HH24:MI:SS')");
	CHECK(KeyLiteral(KeyKind::DATE, "31-JAN-24") == "");
	CHECK(KeyLiteral(KeyKind::TIMESTAMP, "2024-01-31T10:20:30.123456") ==
	      "TO_TIMESTAMP('2024-01-31 10:20:30.123456', 'YYYY-MM-DD HH24:MI:SS.FF')");
	CHECK(KeyLiteral(KeyKind::TIMESTAMP, "2024-01-31T10:20:30") ==
	      "TO_TIMESTAMP('2024-01-31 10:20:30', 'YYYY-MM-DD HH24:MI:SS')");

	CHECK(KeyLiteral(KeyKind::ROWID, "AAAR3sAAEAAAACXAAA") == "CHARTOROWID('AAAR3sAAEAAAACXAAA')");
	CHECK(KeyLiteral(KeyKind::ROWID, "") == "");
}

//! "After this row" over a composite key, expanded the way Oracle needs it.
void TestSeekPredicate() {
	using ofquack::SeekPredicate;

	CHECK(SeekPredicate({"\"ID\""}, {"42"}) == "(\"ID\" > 42)");
	CHECK(SeekPredicate({"\"A\"", "\"B\""}, {"1", "'x'"}) == "(\"A\" > 1 OR (\"A\" = 1 AND \"B\" > 'x'))");
	CHECK(SeekPredicate({"\"A\"", "\"B\"", "\"C\""}, {"1", "2", "3"}) ==
	      "(\"A\" > 1 OR (\"A\" = 1 AND \"B\" > 2) OR (\"A\" = 1 AND \"B\" = 2 AND \"C\" > 3))");
}

//! Sorting by a LOB is ORA-00932, so those columns have to stay out of an
//! ordering that exists only to make paging deterministic.
void TestSortableOracleTypes() {
	using ofquack::IsSortableOracleType;

	CHECK(IsSortableOracleType("VARCHAR2"));
	CHECK(IsSortableOracleType("NUMBER"));
	CHECK(IsSortableOracleType("DATE"));
	CHECK(IsSortableOracleType("TIMESTAMP(6)"));

	CHECK(!IsSortableOracleType("CLOB"));
	CHECK(!IsSortableOracleType("clob"));
	CHECK(!IsSortableOracleType("NCLOB"));
	CHECK(!IsSortableOracleType("BLOB"));
	CHECK(!IsSortableOracleType("LONG RAW"));
	CHECK(!IsSortableOracleType("XMLTYPE"));

	// An unknown type is assumed sortable: dropping columns from the order for
	// no reason weakens it for every type the map has not learned yet.
	CHECK(IsSortableOracleType("SOME_FUTURE_TYPE"));
	CHECK(IsSortableOracleType(""));
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

	// Oracle writes a value below one without its integer part, so a column of
	// amounts arrives as ".84" and not "0.84". Read as text, GL_JE_LINES.ENTERED_DR
	// came back VARCHAR on a live instance.
	const auto no_integer_part = InferColumnType({".84", "0", "-.5"});
	CHECK(no_integer_part.type == InferredType::DECIMAL);
	CHECK(no_integer_part.scale == 2);
	CHECK(InferColumnType({".84"}).type == InferredType::DECIMAL);
	CHECK(InferColumnType({"-.84"}).type == InferredType::DECIMAL);
	// A bare separator is not a number, with or without a sign.
	CHECK(InferColumnType({"."}).type == InferredType::VARCHAR);
	CHECK(InferColumnType({"-."}).type == InferredType::VARCHAR);
	CHECK(InferColumnType({".x"}).type == InferredType::VARCHAR);
}

//! A NUMBER with nothing declared has no lossless mapping, so the choice of
//! loss belongs to whoever is going to read the column.
void TestOracleNumberModes() {
	using ofquack::InferredType;
	using ofquack::MapOracleType;
	using ofquack::NumberMode;

	const auto as_double = MapOracleType("NUMBER", 0, 0, NumberMode::DOUBLE);
	CHECK(as_double.type == InferredType::DOUBLE);
	CHECK(as_double.lossy);

	const auto as_decimal = MapOracleType("NUMBER", 0, 0, NumberMode::DECIMAL);
	CHECK(as_decimal.type == InferredType::DECIMAL);
	CHECK(as_decimal.scale == ofquack::UNCONSTRAINED_DECIMAL_SCALE);
	// Not DECIMAL(38,0): that read Oracle's ".84" as 1, which is the bug the
	// whole mapping exists to avoid.
	CHECK(as_decimal.scale > 0);
	CHECK(as_decimal.lossy);

	// Text is the only mode that gives nothing up, which is why it is the only
	// one not marked lossy.
	const auto as_text = MapOracleType("NUMBER", 0, 0, NumberMode::TEXT);
	CHECK(as_text.type == InferredType::VARCHAR);
	CHECK(!as_text.lossy);

	// A declared precision or scale is a fact, not a choice: the mode has no say
	// over it and nothing is lost.
	for (const auto mode : {NumberMode::DOUBLE, NumberMode::DECIMAL, NumberMode::TEXT}) {
		CHECK(MapOracleType("NUMBER", 18, 0, mode).type == InferredType::BIGINT);
		CHECK(!MapOracleType("NUMBER", 18, 0, mode).lossy);
		const auto money = MapOracleType("NUMBER", 12, 2, mode);
		CHECK(money.type == InferredType::DECIMAL);
		CHECK(money.scale == 2);
		CHECK(!money.lossy);
		// Nor over anything that was never a number.
		CHECK(MapOracleType("VARCHAR2", 0, 0, mode).type == InferredType::VARCHAR);
		CHECK(MapOracleType("DATE", 0, 0, mode).type == InferredType::TIMESTAMP);
	}

	// The binary floating types carry no precision either and follow the mode.
	CHECK(MapOracleType("BINARY_DOUBLE", 0, 0, NumberMode::TEXT).type == InferredType::VARCHAR);
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
	const auto tables = ofquack::metadata::TablesAfter(ofquack::metadata::DICTIONARY_SCHEMA, {"TABLE", "VIEW"}, "", "", 400);
	// FND_VIEWS and FND_TABLES, not ALL_TABLES: only Fusion's own dictionary
	// carries TABLE_ID, and TABLE_ID is how columns are found.
	CHECK(Contains(tables, "FROM FND_VIEWS"));
	CHECK(Contains(tables, "FROM FND_TABLES"));
	CHECK(Contains(tables, "t.table_id AS TABLE_ID"));
	CHECK(Contains(tables, "'TABLE','VIEW'"));

	const auto columns = ofquack::metadata::ColumnsByTableIds(ofquack::metadata::DICTIONARY_SCHEMA, {"101", "102"});
	CHECK(Contains(columns, "FROM FND_COLUMNS c"));
	CHECK(Contains(columns, "JOIN FND_TABLES t ON c.table_id = t.table_id"));
	CHECK(Contains(columns, "IN (101,102)"));
	// Both column queries have to shift the aliases the same way round, or one
	// of them arrives at the mapper transposed. This one used to select the
	// scale as DECIMAL_DIGITS and a literal radix 10 as NUM_PREC_RADIX, so
	// GL_JE_LINES.JE_HEADER_ID -- NUMBER(18,0) in FND_COLUMNS on a live
	// instance -- reached it as precision 0, scale 10 and became
	// DECIMAL(38,10) instead of BIGINT.
	CHECK(Contains(columns, "c.\"PRECISION\" AS DECIMAL_DIGITS"));
	CHECK(Contains(columns, "c.\"SCALE\" AS NUM_PREC_RADIX"));
	CHECK(!Contains(columns, "THEN 10 ELSE NULL END AS NUM_PREC_RADIX"));
	CHECK(Contains(ofquack::metadata::ColumnsOfViews(ofquack::metadata::DICTIONARY_SCHEMA, "V"), "data_precision AS DECIMAL_DIGITS"));
	CHECK(Contains(ofquack::metadata::ColumnsOfViews(ofquack::metadata::DICTIONARY_SCHEMA, "V"), "data_scale AS NUM_PREC_RADIX"));

	// Views are not in FND_COLUMNS at all, and a concrete object name is an
	// equality comparison: underscores in it must not become LIKE wildcards.
	const auto view_columns = ofquack::metadata::ColumnsOfViews(ofquack::metadata::DICTIONARY_SCHEMA, "GL_BALANCES_V");
	CHECK(Contains(view_columns, "FROM all_tab_columns"));
	CHECK(Contains(view_columns, "table_name = 'GL_BALANCES_V'"));
	CHECK(!Contains(view_columns, "UPPER(table_name)"));
	CHECK(!Contains(view_columns, "table_name LIKE"));
	CHECK(Contains(ofquack::metadata::PrimaryKeys(ofquack::metadata::DICTIONARY_SCHEMA, "T"), "constraint_type = 'P'"));
	CHECK(Contains(ofquack::metadata::ForeignKeys(ofquack::metadata::DICTIONARY_SCHEMA, "T"), "constraint_type = 'R'"));
	// The predicate, not the CASE in the select list, which is always there.
	CHECK(Contains(ofquack::metadata::Indexes(ofquack::metadata::DICTIONARY_SCHEMA, "T", true), "AND idx.uniqueness = 'UNIQUE'"));
	CHECK(!Contains(ofquack::metadata::Indexes(ofquack::metadata::DICTIONARY_SCHEMA, "T", false), "AND idx.uniqueness = 'UNIQUE'"));

	// Every object-name lookup compares the bare column against an upper-cased
	// value. Oracle stores dictionary object names in upper case, so UPPER() on
	// the column matches nothing extra and only costs the index -- and these run
	// once per attached table, against dictionary views the size of ALL_INDEXES.
	// The caller's spelling is what gets normalised.
	CHECK(Contains(ofquack::metadata::PrimaryKeys(ofquack::metadata::DICTIONARY_SCHEMA, "gl_je_lines"), "AND c.table_name = 'GL_JE_LINES'"));
	CHECK(Contains(ofquack::metadata::ForeignKeys(ofquack::metadata::DICTIONARY_SCHEMA, "gl_je_lines"), "AND c.table_name = 'GL_JE_LINES'"));
	CHECK(Contains(ofquack::metadata::Indexes(ofquack::metadata::DICTIONARY_SCHEMA, "gl_je_lines", true), "AND idx.table_name = 'GL_JE_LINES'"));
	CHECK(!Contains(ofquack::metadata::PrimaryKeys(ofquack::metadata::DICTIONARY_SCHEMA, "T"), "UPPER("));
	CHECK(!Contains(ofquack::metadata::ForeignKeys(ofquack::metadata::DICTIONARY_SCHEMA, "T"), "UPPER("));
	CHECK(!Contains(ofquack::metadata::Indexes(ofquack::metadata::DICTIONARY_SCHEMA, "T", false), "UPPER("));
	CHECK(!Contains(ofquack::metadata::ColumnsOfViews(ofquack::metadata::DICTIONARY_SCHEMA, "T"), "UPPER("));
	// The one UPPER that stays: an aggregate over the whole union, not a
	// predicate. The listing collapses a name that is both a table and a view,
	// so counting rows would report every complete listing as short.
	CHECK(Contains(ofquack::metadata::TableCount({}), "COUNT(DISTINCT UPPER(t.table_name))"));
}

//! These statements are built by concatenation, and the JDBC driver interpolates
//! names into them raw -- so an apostrophe in a name breaks the statement, and
//! could carry more than a name.
void TestMetadataQueriesEscapeLiterals() {
	CHECK(ofquack::metadata::QuoteLiteral("O'Brien") == "O''Brien");
	const auto sql = ofquack::metadata::PrimaryKeys(ofquack::metadata::DICTIONARY_SCHEMA, "T' OR '1'='1");
	CHECK(Contains(sql, "T'' OR ''1''=''1"));

	// A non-numeric TABLE_ID never reaches the statement.
	const auto columns = ofquack::metadata::ColumnsByTableIds(ofquack::metadata::DICTIONARY_SCHEMA, {"1", "2); DROP TABLE x--", "3"});
	CHECK(Contains(columns, "IN (1,3)"));
	CHECK(!Contains(columns, "DROP TABLE"));
}

void TestOffsetPagination() {
	// Columns still page by OFFSET: a batch of ten tables is a few hundred
	// rows, so depth never becomes a problem there.
	const auto first = ofquack::metadata::PaginateByOffset("SELECT a FROM t ORDER BY a", 0, 400);
	CHECK(first == "SELECT a FROM t ORDER BY a OFFSET 0 ROWS FETCH NEXT 400 ROWS ONLY");
	CHECK(!Contains(first, "ROWNUM"));
}

//! The table listing seeks from the last name instead, because OFFSET paging
//! gets more expensive with depth and is correspondingly more exposed to report
//! timeouts and resource limits. Seeking keeps every page's cost flat.
void TestTableListingSeeksRatherThanOffsets() {
	using ofquack::metadata::TablesAfter;

	const auto first = TablesAfter(ofquack::metadata::DICTIONARY_SCHEMA, {"TABLE", "VIEW"}, "", "", ofquack::metadata::TABLE_LIST_PAGE_SIZE);
	CHECK(!Contains(first, "OFFSET"));
	CHECK(Contains(first, "FETCH FIRST 2000 ROWS ONLY"));
	CHECK(Contains(first, "ORDER BY t.table_name, t.table_type"));

	// The seek compares the ordering pair, since Oracle has no row-value
	// comparison outside IN.
	const auto next = TablesAfter(ofquack::metadata::DICTIONARY_SCHEMA, {"TABLE", "VIEW"}, "GL_JE_HEADERS", "TABLE", 400);
	CHECK(Contains(next, "t.table_name > 'GL_JE_HEADERS'"));
	CHECK(Contains(next, "t.table_name = 'GL_JE_HEADERS' AND t.table_type > 'TABLE'"));
	CHECK(!Contains(next, "OFFSET"));

	// A name with an apostrophe must not break out of the literal.
	CHECK(Contains(TablesAfter(ofquack::metadata::DICTIONARY_SCHEMA, {}, "O'BRIEN", "TABLE", 10), "'O''BRIEN'"));
}

//! The owner was a compile-time constant, so a deployment whose dictionary does
//! not live under FUSION could not be reached at all. It is a secret parameter
//! now, which also means it is user input in a statement built by concatenation.
void TestMetadataQueriesTakeTheSchema() {
	using namespace ofquack::metadata;

	// The predicates -- these decide what the query can see.
	CHECK(Contains(ColumnsOfViews("CUSTOM", "V"), "WHERE owner = 'CUSTOM'"));
	CHECK(Contains(PrimaryKeys("CUSTOM", "T"), "AND c.owner = 'CUSTOM'"));
	CHECK(Contains(ForeignKeys("CUSTOM", "T"), "AND c.owner = 'CUSTOM'"));
	CHECK(Contains(Indexes("CUSTOM", "T", true), "WHERE idx.owner = 'CUSTOM'"));
	// And the reported schema, which would otherwise claim FUSION for rows that
	// did not come from it.
	CHECK(Contains(TablesAfter("CUSTOM", {}, "", "", 10), "'CUSTOM' AS TABLE_SCHEM"));
	CHECK(Contains(ColumnsByTableIds("CUSTOM", {"1"}), "'CUSTOM' AS TABLE_SCHEM"));

	// Oracle stores object owners in upper case, and the predicates compare the
	// bare column, so the caller's spelling is what gets normalised.
	CHECK(Contains(PrimaryKeys("custom", "T"), "AND c.owner = 'CUSTOM'"));

	// It reaches the statement by concatenation like every other name here.
	CHECK(Contains(ColumnsOfViews("O'BRIEN", "V"), "WHERE owner = 'O''BRIEN'"));
	// The apostrophe is doubled, so the tail stays inside the literal instead of
	// closing it and becoming another predicate.
	CHECK(Contains(Indexes("X' OR 1=1--", "T", false), "idx.owner = 'X'' OR 1=1--'"));

	// Nothing quietly falls back to the default once a schema is given.
	CHECK(!Contains(PrimaryKeys("CUSTOM", "T"), "FUSION"));
	CHECK(Contains(PrimaryKeys(DICTIONARY_SCHEMA, "T"), "AND c.owner = 'FUSION'"));
}

//! The count exists to be compared against what a listing produced, so it has
//! to count the same things. The listing collapses a name that exists as both
//! a table and a view onto one entry; counting rows of the union would exceed
//! it by however many names overlap, and every complete listing would then be
//! reported as short.
void TestTableCountCountsDistinctNames() {
	const auto sql = ofquack::metadata::TableCount({"TABLE", "VIEW"});
	CHECK(Contains(sql, "COUNT(DISTINCT UPPER(t.table_name))"));
	CHECK(Contains(sql, "FND_VIEWS"));
	CHECK(Contains(sql, "FND_TABLES"));
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
	// NUMBER with nothing declared has no scale to give DECIMAL, and the only
	// one available was zero -- which read GL_JE_LINES.ENTERED_DR, an amount, as
	// a whole number and rounded `.84` to 1. Every Fusion amount column is
	// declared this way.
	CHECK(MapOracleType("NUMBER", 0, 0).type == InferredType::DOUBLE);
	// The genuinely binary types carry no precision either, and DOUBLE is what
	// they actually are.
	CHECK(MapOracleType("BINARY_DOUBLE", 0, 0).type == InferredType::DOUBLE);
	CHECK(MapOracleType("BINARY_FLOAT", 0, 0).type == InferredType::DOUBLE);
	CHECK(MapOracleType("FLOAT", 0, 0).type == InferredType::DOUBLE);
	// FND's single-letter code for a number, which never carries precision.
	CHECK(MapOracleType("N", 0, 0).type == InferredType::DOUBLE);
	// A declared scale is exact and stays exact: NUMBER(*,2) keeps DECIMAL.
	const auto scaled_only = MapOracleType("NUMBER", 0, 2);
	CHECK(scaled_only.type == InferredType::DECIMAL);
	CHECK(scaled_only.scale == 2);

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

//! Half-open means one probe, not "everyone who arrives after the wait".
//! Letting them all through is the stampede into a sick instance the breaker
//! exists to prevent, and with BI Publisher each of them leaves a session
//! behind on a server that is already struggling.
void TestBreakerAdmitsOnlyOneProbe() {
	ofquack::CircuitBreaker breaker(ofquack::CircuitBreakerSettings {1, 60000});
	TestClock clock;
	breaker.SetClockForTesting(clock.Fn());

	breaker.RecordFailure();
	clock.Advance(61000);

	breaker.RequireClosed("host");
	// The probe is out and has not reported back, so the next caller waits.
	CHECK(Throws([&]() { breaker.RequireClosed("host"); }));
	CHECK(Throws([&]() { breaker.RequireClosed("host"); }));

	// Once it reports, the breaker is closed and everyone goes through.
	breaker.RecordSuccess();
	breaker.RequireClosed("host");
	breaker.RequireClosed("host");

	// The same holds after a failed probe: the wait restarts, and when it is
	// over exactly one caller gets to try again.
	breaker.RecordFailure();
	clock.Advance(61000);
	breaker.RequireClosed("host");
	CHECK(Throws([&]() { breaker.RequireClosed("host"); }));
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
    {"parse rows sanitizes bare ampersand", TestParseRowsSanitizesBareAmpersand},
    {"parse rows preserves valid entities", TestParseRowsPreservesValidEntities},
    {"parse rows keeps angle brackets inside values", TestParseRowsKeepsAngleBracketsInsideValues},
    {"parse rows drops invalid controls", TestParseRowsDropsInvalidControlCharacters},
    {"a truncated block keeps the complete rows", TestTruncatedBlockKeepsTheCompleteRows},
    {"truncated before the first row is reported", TestTruncatedBeforeTheFirstRowIsReported},
    {"a damaged result block is reported", TestDamagedResultBlockIsReported},
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
    {"metadata queries take the schema", TestMetadataQueriesTakeTheSchema},
    {"metadata queries escape literals", TestMetadataQueriesEscapeLiterals},
    {"offset pagination", TestOffsetPagination},
    {"table listing seeks rather than offsets", TestTableListingSeeksRatherThanOffsets},
    {"table count counts distinct names", TestTableCountCountsDistinctNames},
    {"oracle type mapping", TestOracleTypeMapping},
    {"oracle number modes", TestOracleNumberModes},
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
    {"breaker admits only one probe", TestBreakerAdmitsOnlyOneProbe},
    {"breaker error is informative", TestBreakerErrorIsInformative},
    {"order by detection", TestOrderByDetection},
    {"ordering rewrites", TestOrderingRewrites},
    {"order probe", TestOrderProbe},
    {"key literals", TestKeyLiterals},
    {"seek predicate", TestSeekPredicate},
    {"sortable oracle types", TestSortableOracleTypes},
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
