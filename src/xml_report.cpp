#include "ofquack/xml_report.hpp"

#include <cctype>

#include "base64.h"

#include <stdexcept>
#include <tinyxml2.h>
#include <unordered_set>

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
		if (inner_doc.Parse(inner) != tx2::XML_SUCCESS) {
			// Skipping it would hand back the rows of the blocks that did parse
			// and call that the answer. A report that arrives damaged has to be
			// reported as damaged: a partial result that looks whole is the one
			// failure the caller cannot detect.
			throw std::runtime_error(std::string("A result block of the report is not valid XML: ") +
			                         inner_doc.ErrorStr());
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
