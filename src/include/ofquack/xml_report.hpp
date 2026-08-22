#pragma once

#include <string>
#include <unordered_map>
#include <vector>

namespace ofquack {

//! One report row, keyed by column name.
//!
//! A column absent from the map is SQL NULL, not an empty string: dbms_xmlgen
//! omits NULL elements entirely, while a genuinely empty value still arrives as
//! an empty element. The two must not be collapsed.
using ReportRow = std::unordered_map<std::string, std::string>;

struct ParsedReport {
	std::vector<ReportRow> rows;
	//! Column names in the order the document first mentions them, which is the
	//! order of the SELECT list. Deliberately not sorted.
	std::vector<std::string> columns;
};

//! Pulls the report payload out of a SOAP response: locates <reportBytes>
//! anywhere under the Body and base64-decodes it.
//!
//! Every lookup is by *local* name, with any namespace prefix stripped, because
//! Fusion is not consistent about which prefix it uses for these elements.
//! Throws if the response is not a report -- a SOAP fault included.
std::string ExtractReportXML(const std::string &soap_xml);

//! Parses the decoded payload into rows plus the column list.
//!
//! The payload nests two documents: each <RESULT> element's *text* is itself an
//! escaped XML document (<ROWSET><ROW>…), so it is parsed again as a separate
//! document rather than walked as child nodes.
ParsedReport ParseRows(const std::string &xml);

} // namespace ofquack
