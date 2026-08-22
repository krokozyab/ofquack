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
#include "ofquack/soap_envelope.hpp"
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
