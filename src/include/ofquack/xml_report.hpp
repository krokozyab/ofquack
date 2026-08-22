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
	//! True when a result block was cut off partway through and only the rows
	//! that arrived whole are here. The report has a limit on how much one
	//! response carries and says nothing when it is reached, so the block ends
	//! mid-element; the rows before that point are good, the rest never came.
	//! A caller that pages by the rows it received is unaffected. A caller that
	//! asked for everything in one request has lost data and must say so.
	bool truncated = false;
	//! Size of the block that was cut off, for the message that reports it.
	size_t truncated_at_bytes = 0;
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
