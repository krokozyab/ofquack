#include "ofquack/soap_envelope.hpp"

#include <sstream>

namespace ofquack {

std::string EscapeCdata(const std::string &text) {
	static const std::string TERMINATOR = "]]>";
	// "]]" stays in the current section, ">" starts a fresh one; a parser
	// concatenates the two sections back into the original "]]>".
	static const std::string REPLACEMENT = "]]]]><![CDATA[>";

	std::string escaped;
	size_t search_from = 0;
	for (;;) {
		const auto found = text.find(TERMINATOR, search_from);
		if (found == std::string::npos) {
			escaped.append(text, search_from, std::string::npos);
			return escaped;
		}
		escaped.append(text, search_from, found - search_from);
		escaped.append(REPLACEMENT);
		search_from = found + TERMINATOR.size();
	}
}

std::string BuildEnvelope(const std::string &sql, const std::string &report_path) {
	std::ostringstream oss;
	oss << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
	    << "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\""
	    << " xmlns:pub=\"http://xmlns.oracle.com/oxp/service/PublicReportService\">"
	    << "<soap:Body><pub:runReport><pub:reportRequest>"
	    << "<pub:attributeFormat>xml</pub:attributeFormat>"
	    << "<pub:byPassCache>true</pub:byPassCache>"
	    << "<pub:reportAbsolutePath>" << report_path << "</pub:reportAbsolutePath>"
	    << "<pub:sizeOfDataChunkDownload>-1</pub:sizeOfDataChunkDownload>"
	    << "<pub:parameterNameValues><pub:item>"
	    << "<pub:name>p_sql</pub:name><pub:values>"
	    << "<pub:item><![CDATA[" << EscapeCdata(sql) << "]]></pub:item>"
	    << "</pub:values></pub:item></pub:parameterNameValues>"
	    << "</pub:reportRequest></pub:runReport></soap:Body></soap:Envelope>";
	return oss.str();
}

} // namespace ofquack
