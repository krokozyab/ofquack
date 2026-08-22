#include "ofquack/xml_report.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>

#include "base64.h"

#include <stdexcept>
#include <tinyxml2.h>
#include <unordered_set>
#include <vector>

// Aliased to avoid a symbol collision with MSXML on Windows.
namespace tx2 = tinyxml2;

namespace ofquack {

namespace {

//! Element name with any namespace prefix removed ("pub:reportBytes" -> "reportBytes").
std::string LocalName(const tx2::XMLElement &element) {
	std::string full = element.Name();
	const auto pos = full.find(':');
	return pos == std::string::npos ? full : full.substr(pos + 1);
}

//! True when the text holds nothing but whitespace.
bool IsBlank(const char *text) {
	for (const char *c = text; *c; c++) {
		if (!std::isspace(static_cast<unsigned char>(*c))) {
			return false;
		}
	}
	return true;
}

//! Direct child with the given local name, or nullptr.
tx2::XMLElement *FindChild(tx2::XMLNode &parent, const std::string &local_name) {
	for (auto node = parent.FirstChild(); node; node = node->NextSibling()) {
		auto element = node->ToElement();
		if (element && LocalName(*element) == local_name) {
			return element;
		}
	}
	return nullptr;
}

//! First descendant with the given local name, depth first, or nullptr.
tx2::XMLElement *FindDescendant(tx2::XMLNode &node, const std::string &local_name) {
	for (auto child = node.FirstChild(); child; child = child->NextSibling()) {
		auto element = child->ToElement();
		if (element && LocalName(*element) == local_name) {
			return element;
		}
		if (auto found = FindDescendant(*child, local_name)) {
			return found;
		}
	}
	return nullptr;
}

void CollectResultElements(tx2::XMLNode &node, std::vector<tx2::XMLElement *> &out) {
	for (auto child = node.FirstChild(); child; child = child->NextSibling()) {
		if (auto element = child->ToElement()) {
			if (LocalName(*element) == "RESULT") {
				out.push_back(element);
			}
			CollectResultElements(*child, out);
		}
	}
}

//! XML 1.0 characters permitted by the fifth edition. This is used only for
//! numeric character references; UTF-8 bytes are otherwise copied verbatim.
bool IsXml10Character(uint32_t value) {
	return value == 0x09 || value == 0x0A || value == 0x0D || (value >= 0x20 && value <= 0xD7FF) ||
	       (value >= 0xE000 && value <= 0xFFFD) || (value >= 0x10000 && value <= 0x10FFFF);
}

bool IsDigitForBase(char value, uint32_t base, uint32_t &digit) {
	if (value >= '0' && value <= '9') {
		digit = static_cast<uint32_t>(value - '0');
	} else if (base == 16 && value >= 'a' && value <= 'f') {
		digit = static_cast<uint32_t>(value - 'a' + 10);
	} else if (base == 16 && value >= 'A' && value <= 'F') {
		digit = static_cast<uint32_t>(value - 'A' + 10);
	} else {
		return false;
	}
	return digit < base;
}

//! True when the ampersand at `at` begins an entity that a strict XML 1.0
//! parser can consume. Requiring the semicolon prevents a stray "&amp" from
//! swallowing following text.
bool IsValidEntity(const std::string &xml, size_t at) {
	static const char *NAMED_ENTITIES[] = {"&amp;", "&lt;", "&gt;", "&quot;", "&apos;"};
	for (const auto entity : NAMED_ENTITIES) {
		if (xml.compare(at, std::char_traits<char>::length(entity), entity) == 0) {
			return true;
		}
	}

	if (at + 3 >= xml.size() || xml[at + 1] != '#') {
		return false;
	}
	size_t cursor = at + 2;
	uint32_t base = 10;
	if (xml[cursor] == 'x') {
		base = 16;
		cursor++;
	}
	const size_t first_digit = cursor;
	uint32_t code_point = 0;
	for (; cursor < xml.size() && xml[cursor] != ';'; cursor++) {
		uint32_t digit = 0;
		if (!IsDigitForBase(xml[cursor], base, digit) || code_point > (0x10FFFF - digit) / base) {
			return false;
		}
		code_point = code_point * base + digit;
	}
	return cursor > first_digit && cursor < xml.size() && xml[cursor] == ';' && IsXml10Character(code_point);
}

bool IsNameStart(char c) {
	return std::isalpha(static_cast<unsigned char>(c)) || c == '_' || c == ':';
}

bool IsNameChar(char c) {
	return IsNameStart(c) || std::isdigit(static_cast<unsigned char>(c)) || c == '-' || c == '.';
}

//! What a '<' at `at` begins, if it is a tag at all.
struct TagScan {
	bool is_tag = false;
	bool closing = false;
	bool self_closing = false;
	std::string name;
	size_t end = 0; //!< index just past the '>'
};

//! Reads a start, end or empty-element tag at `at`. Loose about attributes --
//! the report writes `xsi:nil = "true"` with spaces, and tinyxml2 accepts it
//! -- but strict about the name, and a '<' before the closing '>' means this
//! was never a tag.
TagScan ScanTag(const std::string &xml, size_t at) {
	TagScan scan;
	size_t i = at + 1;
	if (i < xml.size() && xml[i] == '/') {
		scan.closing = true;
		i++;
	}
	if (i >= xml.size() || !IsNameStart(xml[i])) {
		return scan;
	}
	const auto name_start = i;
	while (i < xml.size() && IsNameChar(xml[i])) {
		i++;
	}
	scan.name = xml.substr(name_start, i - name_start);
	char quote = '\0';
	for (; i < xml.size(); i++) {
		const char c = xml[i];
		if (quote) {
			if (c == quote) {
				quote = '\0';
			}
			continue;
		}
		if (c == '"' || c == '\'') {
			quote = c;
		} else if (c == '<') {
			return scan;
		} else if (c == '>') {
			scan.self_closing = !scan.closing && i > name_start && xml[i - 1] == '/';
			scan.is_tag = true;
			scan.end = i + 1;
			return scan;
		} else if (scan.closing && !std::isspace(static_cast<unsigned char>(c))) {
			// An end tag carries nothing but its name.
			return scan;
		}
	}
	return scan;
}

//! Repairs the data-level defects seen in BI Publisher output: a stray '&', a
//! control character, and a '<' inside a value -- a table described as
//! "a dictionary of <area_id, date> combinations" arrives with the brackets
//! unescaped, and that is data, not markup.
//!
//! The document's shape is what makes the last one decidable: ROWSET holds
//! ROWs, a ROW holds one element per column, and a column holds text and
//! nothing else. So inside a column, the only '<' that is markup is the
//! column's own end tag; every other one is escaped. Outside a column the
//! text is left alone.
//!
//! Document structure is deliberately not repaired: a truncated response must
//! remain an error rather than become an apparently complete result.
std::string SanitizeInnerXml(const std::string &xml) {
	std::string sanitized;
	sanitized.reserve(xml.size());
	std::vector<std::string> open;
	// Inside a column: the element on top of the stack is a child of a ROW.
	const auto in_column = [&]() { return open.size() >= 2 && open[open.size() - 2] == "ROW"; };

	for (size_t i = 0; i < xml.size(); i++) {
		const auto byte = static_cast<unsigned char>(xml[i]);
		if (byte == '<') {
			// Prolog, comment and CDATA are copied through outside a column;
			// inside one they are text, the report never writes them there.
			if (!in_column() && i + 1 < xml.size() && (xml[i + 1] == '?' || xml[i + 1] == '!')) {
				const char *terminator = xml[i + 1] == '?' ? "?>" : (xml.compare(i, 9, "<![CDATA[") == 0 ? "]]>" : ">");
				const auto end = xml.find(terminator, i);
				const auto stop = end == std::string::npos ? xml.size() : end + std::char_traits<char>::length(terminator);
				sanitized.append(xml, i, stop - i);
				i = stop - 1;
				continue;
			}
			const auto tag = ScanTag(xml, i);
			const bool closes_column = tag.is_tag && tag.closing && in_column() && tag.name == open.back();
			if (in_column() && !closes_column) {
				sanitized += "&lt;";
				continue;
			}
			if (!tag.is_tag) {
				// Not inside a column and not a tag either: left for the parser
				// to report, since guessing here would hide real damage.
				sanitized.push_back('<');
				continue;
			}
			if (tag.closing) {
				if (!open.empty() && open.back() == tag.name) {
					open.pop_back();
				}
			} else if (!tag.self_closing) {
				open.push_back(tag.name);
			}
			sanitized.append(xml, i, tag.end - i);
			i = tag.end - 1;
			continue;
		}
		if (byte == '&') {
			if (!IsValidEntity(xml, i)) {
				sanitized += "&amp;";
			} else {
				sanitized.push_back('&');
			}
			continue;
		}
		// Treat bytes above ASCII as opaque UTF-8. Only forbidden C0 controls
		// can be identified safely one byte at a time.
		if (byte < 0x20 && byte != '\t' && byte != '\n' && byte != '\r') {
			continue;
		}
		sanitized.push_back(xml[i]);
	}
	return sanitized;
}

//! The rows that arrived whole from a block that was cut off: everything up to
//! the last </ROW>, closed again. Empty when no row completed. A </ROW> inside
//! a value cannot mislead this, since the value would carry it escaped.
std::string CompleteRowsOf(const std::string &xml) {
	static const std::string ROW_END = "</ROW>";
	const auto last_row_end = xml.rfind(ROW_END);
	if (last_row_end == std::string::npos) {
		return {};
	}
	return xml.substr(0, last_row_end + ROW_END.size()) + "</ROWSET>";
}

//! A window of the text around the line the parser complained about, with the
//! line breaks made visible. A parse error names a line and nothing else, and
//! the line is inside a document nobody else ever sees -- this is the only way
//! for anyone to learn what is actually there.
std::string Excerpt(const std::string &text, int line) {
	size_t at = 0;
	for (int current = 1; current < line && at < text.size(); current++) {
		const auto next = text.find('\n', at);
		if (next == std::string::npos) {
			break;
		}
		at = next + 1;
	}
	constexpr size_t RADIUS = 240;
	const auto from = at > RADIUS ? at - RADIUS : 0;
	auto window = text.substr(from, std::min(text.size() - from, 2 * RADIUS));
	std::string shown;
	shown.reserve(window.size());
	for (const char c : window) {
		if (c == '\n') {
			shown += "\\n";
		} else if (c == '\r') {
			shown += "\\r";
		} else if (c == '\t') {
			shown += "\\t";
		} else {
			shown.push_back(c);
		}
	}
	return shown;
}

bool HasInvalidXml10Control(const std::string &xml) {
	for (const auto value : xml) {
		const auto byte = static_cast<unsigned char>(value);
		if (byte < 0x20 && byte != '\t' && byte != '\n' && byte != '\r') {
			return true;
		}
	}
	return false;
}

} // namespace

std::string ExtractReportXML(const std::string &soap_xml) {
	tx2::XMLDocument doc;
	if (doc.Parse(soap_xml.c_str()) != tx2::XML_SUCCESS) {
		throw std::runtime_error("Failed to parse SOAP XML");
	}
	auto envelope = FindChild(doc, "Envelope");
	if (!envelope) {
		throw std::runtime_error("Missing SOAP Envelope");
	}
	auto body = FindChild(*envelope, "Body");
	if (!body) {
		throw std::runtime_error("Missing SOAP Body");
	}
	auto report_bytes = FindDescendant(*body, "reportBytes");
	if (!report_bytes || !report_bytes->GetText()) {
		throw std::runtime_error("Missing reportBytes in response");
	}
	// The explicit std::string is load-bearing: base64.h only declares its
	// string_view overloads under C++17, so a bare const char* is ambiguous.
	// std::string is the overload that was selected before this target left
	// C++11, so decoding behaviour is unchanged.
	return base64_decode(std::string(report_bytes->GetText()));
}

ParsedReport ParseRows(const std::string &xml) {
	tx2::XMLDocument doc;
	if (doc.Parse(xml.c_str()) != tx2::XML_SUCCESS) {
		throw std::runtime_error("Bad report XML");
	}
	std::vector<tx2::XMLElement *> result_elements;
	CollectResultElements(doc, result_elements);

	ParsedReport report;
	// Tracks which names have been recorded; `report.columns` keeps the order.
	std::unordered_set<std::string> seen_columns;
	for (auto result_element : result_elements) {
		const char *inner = result_element->GetText();
		// A block with no text is a result set with no rows, which is an answer
		// rather than a problem.
		if (!inner || IsBlank(inner)) {
			continue;
		}
		// The text of <RESULT> is a whole escaped document, not child nodes.
		tx2::XMLDocument inner_doc;
		const std::string inner_xml(inner);
		const auto strict_result = inner_doc.Parse(inner);
		// tinyxml2 accepts some forbidden C0 controls despite XML 1.0. Treat
		// that as a failed strict validation so they cannot leak into values.
		const bool invalid_control = HasInvalidXml10Control(inner_xml);
		if (strict_result != tx2::XML_SUCCESS || invalid_control) {
			const std::string strict_error =
			    invalid_control ? "forbidden XML 1.0 control character" : inner_doc.ErrorStr();
			const auto sanitized = SanitizeInnerXml(inner_xml);
			inner_doc.Clear();
			if (inner_doc.Parse(sanitized.c_str()) != tx2::XML_SUCCESS) {
				const std::string sanitized_error = inner_doc.ErrorStr();
				const int failed_line = inner_doc.ErrorLineNum();
				// The report has a limit on how much one response carries, and
				// when it is reached the block simply stops -- mid-element, with
				// no indication that anything is missing. That is what this
				// usually is. The rows before the cut are intact, so they are
				// kept and the block is marked, which lets a caller that pages
				// by the rows it received carry on from the right place. Only
				// complete rows are kept: a cut anywhere else still fails, so a
				// block damaged in the middle is not passed off as whole.
				const auto complete = CompleteRowsOf(sanitized);
				inner_doc.Clear();
				if (complete.empty() || inner_doc.Parse(complete.c_str()) != tx2::XML_SUCCESS) {
					if (complete.empty() && sanitized.find("<ROW>") != std::string::npos) {
						throw std::runtime_error(
						    "The report's response was cut off before its first row was complete (" +
						    std::to_string(sanitized.size()) +
						    " bytes arrived). One row is larger than the report returns in a single response; "
						    "select fewer or narrower columns");
					}
					// Skipping it would hand back the rows of the blocks that did
					// parse and call that the answer. A report that arrives
					// structurally damaged has to be reported as damaged: a
					// partial result that looks whole is the one failure the
					// caller cannot detect.
					// Whether the block ends properly says whether this is a cut
					// (it does not) or damage in the middle (it does).
					const bool ends_properly = sanitized.find("</ROWSET>") != std::string::npos;
					const std::string rows_state =
					    complete.empty() ? "no complete row" : "the rows before the last </ROW> do not parse either";
					throw std::runtime_error(
					    std::string("A result block of the report is not valid XML after conservative sanitization: ") +
					    sanitized_error + " (initial parse: " + strict_error + "). The block is " +
					    std::to_string(sanitized.size()) + " bytes, " +
					    (ends_properly ? "ends with </ROWSET>" : "does not end with </ROWSET>") + ", " + rows_state +
					    ".\nAround line " + std::to_string(failed_line) + ": " + Excerpt(sanitized, failed_line));
				}
				report.truncated = true;
				report.truncated_at_bytes = inner_xml.size();
			}
		}
		auto rowset = FindChild(inner_doc, "ROWSET");
		if (!rowset) {
			throw std::runtime_error("A result block of the report holds no ROWSET element");
		}
		for (auto row = rowset->FirstChildElement("ROW"); row; row = row->NextSiblingElement("ROW")) {
			ReportRow parsed;
			for (auto col = row->FirstChildElement(); col; col = col->NextSiblingElement()) {
				auto name = LocalName(*col);
				const char *text = col->GetText();
				if (seen_columns.insert(name).second) {
					report.columns.push_back(name);
				}
				parsed[std::move(name)] = text ? text : "";
			}
			report.rows.push_back(std::move(parsed));
		}
	}
	return report;
}

} // namespace ofquack
