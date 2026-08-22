#pragma once

#include <set>
#include <string>
#include <unordered_map>
#include <vector>

namespace ofquack {

//! One report row, keyed by column name. Columns absent from a row are absent
//! from the map: dbms_xmlgen drops NULL elements rather than emitting them.
using ReportRow = std::unordered_map<std::string, std::string>;

//! Pulls the report payload out of a SOAP response: locates <reportBytes>
//! anywhere under the Body and base64-decodes it.
//!
//! Every lookup is by *local* name, with any namespace prefix stripped, because
//! Fusion is not consistent about which prefix it uses for these elements.
std::string ExtractReportXML(const std::string &soap_xml);

//! Parses the decoded payload into rows, adding every column it sees to `cols`.
//!
//! The payload nests two documents: each <RESULT> element's *text* is itself an
//! escaped XML document (<ROWSET><ROW>…), so it is parsed again as a separate
//! document rather than walked as child nodes.
std::vector<ReportRow> ParseRows(const std::string &xml, std::set<std::string> &cols);

} // namespace ofquack
