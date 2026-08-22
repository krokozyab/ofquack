// Unit tests for the pure layer: envelope construction and report parsing.
//
// Nothing here touches DuckDB or the network, so this binary builds and runs in
// about a second and can be run on every push.

#include "base64.h"
#include "ofquack/soap_envelope.hpp"
#include "ofquack/xml_report.hpp"

#include <cstdlib>
#include <iostream>
#include <set>
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
	CHECK(Throws([]() {
		ExtractReportXML("<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\"/>");
	}));
	// Envelope and Body present, but no reportBytes: a SOAP fault looks like this.
	CHECK(Throws([]() {
		ExtractReportXML("<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\"><soap:Body>"
		                 "<soap:Fault><soap:Reason><soap:Text>boom</soap:Text></soap:Reason></soap:Fault>"
		                 "</soap:Body></soap:Envelope>");
	}));
}

void TestParseRowsReadsNestedDocument() {
	std::set<std::string> cols;
	const auto rows = ParseRows(MakeReportXML("&lt;ROWSET&gt;"
	                                          "&lt;ROW&gt;&lt;NAME&gt;Alpha&lt;/NAME&gt;&lt;CODE&gt;A&lt;/CODE&gt;&lt;/ROW&gt;"
	                                          "&lt;ROW&gt;&lt;NAME&gt;Beta&lt;/NAME&gt;&lt;CODE&gt;B&lt;/CODE&gt;&lt;/ROW&gt;"
	                                          "&lt;/ROWSET&gt;"),
	                            cols);

	CHECK(rows.size() == 2);
	CHECK(rows[0].at("NAME") == "Alpha");
	CHECK(rows[0].at("CODE") == "A");
	CHECK(rows[1].at("NAME") == "Beta");
	CHECK(cols.size() == 2);
}

void TestParseRowsOmitsNullColumns() {
	std::set<std::string> cols;
	// dbms_xmlgen drops NULL elements, so a row can simply lack a column.
	const auto rows = ParseRows(MakeReportXML("&lt;ROWSET&gt;"
	                                          "&lt;ROW&gt;&lt;NAME&gt;Alpha&lt;/NAME&gt;&lt;CODE&gt;A&lt;/CODE&gt;&lt;/ROW&gt;"
	                                          "&lt;ROW&gt;&lt;NAME&gt;Beta&lt;/NAME&gt;&lt;/ROW&gt;"
	                                          "&lt;/ROWSET&gt;"),
	                            cols);

	CHECK(rows.size() == 2);
	CHECK(rows[1].find("CODE") == rows[1].end());
	// The column still belongs to the schema: another row had it.
	CHECK(cols.count("CODE") == 1);
}

void TestParseRowsKeepsEmptyElementsDistinctFromMissingOnes() {
	std::set<std::string> cols;
	const auto rows = ParseRows(
	    MakeReportXML("&lt;ROWSET&gt;&lt;ROW&gt;&lt;NAME&gt;&lt;/NAME&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;"), cols);

	CHECK(rows.size() == 1);
	CHECK(rows[0].at("NAME").empty());
}

void TestParseRowsHandlesEmptyAndMultipleResults() {
	{
		std::set<std::string> cols;
		const auto rows = ParseRows(MakeReportXML("&lt;ROWSET/&gt;"), cols);
		CHECK(rows.empty());
		CHECK(cols.empty());
	}
	{
		// A large report comes back as several <RESULT> elements.
		std::set<std::string> cols;
		const auto rows =
		    ParseRows("<DATA_DS><G_1>"
		              "<RESULT>&lt;ROWSET&gt;&lt;ROW&gt;&lt;N&gt;1&lt;/N&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;</RESULT>"
		              "<RESULT>&lt;ROWSET&gt;&lt;ROW&gt;&lt;N&gt;2&lt;/N&gt;&lt;/ROW&gt;&lt;/ROWSET&gt;</RESULT>"
		              "</G_1></DATA_DS>",
		              cols);
		CHECK(rows.size() == 2);
		CHECK(rows[0].at("N") == "1");
		CHECK(rows[1].at("N") == "2");
	}
}

void TestParseRowsRejectsUnparseablePayload() {
	std::set<std::string> cols;
	CHECK(Throws([&]() { ParseRows("<DATA_DS><unclosed>", cols); }));
}

//! Records today's behaviour, which is wrong and is scheduled to change: column
//! order comes from a std::set, so it is alphabetical rather than SELECT order.
//! When the query function is rewritten this test should be inverted, not
//! deleted -- it is the thing that proves the fix landed.
void TestColumnOrderIsCurrentlyAlphabetical() {
	std::set<std::string> cols;
	ParseRows(MakeReportXML("&lt;ROWSET&gt;&lt;ROW&gt;"
	                        "&lt;ZETA&gt;z&lt;/ZETA&gt;&lt;ALPHA&gt;a&lt;/ALPHA&gt;"
	                        "&lt;/ROW&gt;&lt;/ROWSET&gt;"),
	           cols);

	const std::vector<std::string> ordered(cols.begin(), cols.end());
	CHECK(ordered.size() == 2);
	CHECK(ordered[0] == "ALPHA"); // document order was ZETA, ALPHA
	CHECK(ordered[1] == "ZETA");
}

struct TestCase {
	const char *name;
	void (*run)();
};

const TestCase TESTS[] = {
    {"envelope carries sql and report path", TestEnvelopeCarriesSqlAndReportPath},
    {"extract ignores namespace prefixes", TestExtractIgnoresNamespacePrefixes},
    {"extract rejects malformed responses", TestExtractRejectsMalformedResponses},
    {"parse rows reads nested document", TestParseRowsReadsNestedDocument},
    {"parse rows omits null columns", TestParseRowsOmitsNullColumns},
    {"parse rows keeps empty elements", TestParseRowsKeepsEmptyElementsDistinctFromMissingOnes},
    {"parse rows handles empty and multiple results", TestParseRowsHandlesEmptyAndMultipleResults},
    {"parse rows rejects unparseable payload", TestParseRowsRejectsUnparseablePayload},
    {"column order is currently alphabetical", TestColumnOrderIsCurrentlyAlphabetical},
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
