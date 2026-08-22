#include "ofquack/soap_envelope.hpp"

#include <sstream>

namespace ofquack {

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
	    << "<pub:item><![CDATA[" << sql << "]]></pub:item>"
	    << "</pub:values></pub:item></pub:parameterNameValues>"
	    << "</pub:reportRequest></pub:runReport></soap:Body></soap:Envelope>";
	return oss.str();
}

} // namespace ofquack
