// Unit tests for the pure layer: envelope construction, report parsing and
// error decoding.
//
// Nothing here touches DuckDB or the network, so this binary builds and runs in
// about a second and can be run on every push.

#include "base64.h"
#include "ofquack/error_decoder.hpp"
#include "ofquack/soap_envelope.hpp"
#include "ofquack/xml_report.hpp"

#include <cstdlib>
#include <iostream>
#include <string>
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
