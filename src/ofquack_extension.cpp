#include <stdexcept>
#include <iostream>
#define DUCKDB_EXTENSION_MAIN
#include "ofquack_extension.hpp"
#include "duckdb.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/extension_util.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/helper.hpp"

#include <curl/curl.h>
#include <tinyxml2.h>
#include "base64.h"

#include <sstream>
#include <unordered_map>
#include <set>
#include <vector>
#include <string>

using namespace duckdb;
using namespace tinyxml2;

struct FusionBindData : public TableFunctionData {
    string endpoint, user, pass, path, sql;
    vector<string> columns;
    vector<unordered_map<string,string>> rows;
    // Removed offset field
};

// Define a new local state struct
struct FusionLocalState : public LocalTableFunctionState {
    idx_t offset = 0;
};

//--------------------------------------------------------------------------------------------------
// 1) CURL helper: accumulate response bytes
//--------------------------------------------------------------------------------------------------
static size_t CurlWrite(void* contents, size_t size, size_t nmemb, void* userp) {
    auto& out = *static_cast<std::string*>(userp);
    out.append((char*)contents, size * nmemb);
    return size * nmemb;
}

//--------------------------------------------------------------------------------------------------
// 2) Build SOAP envelope (mirrors Utils.createSoapEnvelope)
//--------------------------------------------------------------------------------------------------
static std::string BuildEnvelope(const std::string &sql, const std::string &reportPath) {
    std::ostringstream oss;
    oss << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        << "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\""
        << " xmlns:pub=\"http://xmlns.oracle.com/oxp/service/PublicReportService\">"
        << "<soap:Body><pub:runReport><pub:reportRequest>"
        << "<pub:attributeFormat>xml</pub:attributeFormat>"
        << "<pub:byPassCache>true</pub:byPassCache>"
        << "<pub:reportAbsolutePath>" << reportPath << "</pub:reportAbsolutePath>"
        << "<pub:sizeOfDataChunkDownload>-1</pub:sizeOfDataChunkDownload>"
        << "<pub:parameterNameValues><pub:item>"
        << "<pub:name>p_sql</pub:name><pub:values>"
        << "<pub:item><![CDATA[" << sql << "]]></pub:item>"
        << "</pub:values></pub:item></pub:parameterNameValues>"
        << "</pub:reportRequest></pub:runReport></soap:Body></soap:Envelope>";
    return oss.str();
}

//--------------------------------------------------------------------------------------------------
// 3) Send SOAP request and return raw XML
//    (mirrors Utils.sendSqlViaWsdl up to parseXml call)
//--------------------------------------------------------------------------------------------------
static std::string FetchSoap(const std::string &endpoint, const std::string &user, const std::string &pass,
                        const std::string &reportPath, const std::string &sql) {
    // Base64-encode credentials
    std::string creds = user + ":" + pass;
    std::string auth = "Authorization: Basic " +
        base64_encode((const unsigned char*)creds.c_str(), creds.size());

    // Build envelope
    std::string body = BuildEnvelope(sql, reportPath);

    // Curl init
    CURL *curl = curl_easy_init();
    if (!curl) throw std::runtime_error("Failed to init CURL");
    std::string resp;
    struct curl_slist *hdrs = nullptr;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/soap+xml;charset=UTF-8");
    hdrs = curl_slist_append(hdrs, "SOAPAction: #POST");
    hdrs = curl_slist_append(hdrs, auth.c_str());

    curl_easy_setopt(curl, CURLOPT_URL, endpoint.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWrite);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);

    CURLcode code = curl_easy_perform(curl);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    if (code != CURLE_OK) {
        throw std::runtime_error(std::string("SOAP request failed: ") + curl_easy_strerror(code));
    }
    if (resp.rfind("<html", 0) == 0) {
        throw std::runtime_error("Received HTML error page");
    }
    return resp;
}

//--------------------------------------------------------------------------------------------------
// 4) Parse the SOAP XML, extract <reportBytes>, decode, and return the decoded XML
//--------------------------------------------------------------------------------------------------
static std::string ExtractReportXML(const std::string &soap_xml) {
    XMLDocument doc;
    if (doc.Parse(soap_xml.c_str()) != XML_SUCCESS) {
        throw std::runtime_error("Failed to parse SOAP XML");
    }
    // Helper to find a child element by local name, ignoring prefix
    auto find_local = [&](XMLNode *parent, const std::string &local_name) {
        for (auto node = parent->FirstChild(); node; node = node->NextSibling()) {
            auto elem = node->ToElement();
            if (!elem) continue;
            std::string full = elem->Name();
            auto pos = full.find(':');
            std::string local = pos == std::string::npos ? full : full.substr(pos + 1);
            if (local == local_name) return elem;
        }
        return (XMLElement *)nullptr;
    };
    // Find Envelope
    XMLElement *envelope = find_local(&doc, "Envelope");
    if (!envelope) {
        throw std::runtime_error("Missing SOAP Envelope");
    }
    // Find Body under Envelope
    XMLElement *body = find_local(envelope, "Body");
    if (!body) {
        throw std::runtime_error("Missing SOAP Body");
    }
    // Recursively find <reportBytes> by local name
    std::function<XMLElement*(XMLNode*, const std::string&)> find_deep =
        [&](XMLNode *node, const std::string &local_name) -> XMLElement* {
            for (auto child = node->FirstChild(); child; child = child->NextSibling()) {
                auto elem = child->ToElement();
                if (elem) {
                    std::string full = elem->Name();
                    auto pos = full.find(':');
                    std::string local = pos == std::string::npos ? full : full.substr(pos + 1);
                    if (local == local_name) {
                        return elem;
                    }
                }
                auto found = find_deep(child, local_name);
                if (found) {
                    return found;
                }
            }
            return nullptr;
        };
    // Search entire Body subtree for reportBytes
    XMLElement *rb = find_deep(body, "reportBytes");
    if (!rb || !rb->GetText()) {
        throw std::runtime_error("Missing reportBytes in response");
    }
    std::cerr << "[DEBUG] ExtractReportXML: found reportBytes length=" << strlen(rb->GetText()) << std::endl;
    // Decode Base64 content
    return base64_decode(rb->GetText());
}

//--------------------------------------------------------------------------------------------------
// 5) Parse the decoded report XML into rows + collect schema
//    (mirrors Utils.parseXml + createResultSetFromRowNodes)
//--------------------------------------------------------------------------------------------------
static std::vector<std::unordered_map<std::string, std::string>> ParseRows(const std::string &xml, std::set<std::string> &cols) {
    XMLDocument doc;
    if (doc.Parse(xml.c_str()) != XML_SUCCESS) {
        throw std::runtime_error("Bad report XML");
    }
    // Find all <RESULT> elements anywhere in the document
    std::vector<XMLElement*> result_elems;
    std::function<void(XMLNode*)> collect_results = [&](XMLNode *node) {
        for (auto child = node->FirstChild(); child; child = child->NextSibling()) {
            if (auto elem = child->ToElement()) {
                std::string full = elem->Name();
                auto pos = full.find(':');
                std::string local = pos == std::string::npos ? full : full.substr(pos + 1);
                if (local == "RESULT") {
                    result_elems.push_back(elem);
                }
                collect_results(child);
            }
        }
    };
    collect_results(&doc);
    std::vector<std::unordered_map<std::string, std::string>> rows_out;
    // Parse each <RESULT> as its own XML fragment
    for (auto result_elem : result_elems) {
        const char *inner = result_elem->GetText();
        if (!inner) continue;
        XMLDocument inner_doc;
        if (inner_doc.Parse(inner) != XML_SUCCESS) continue;
        auto rowset = inner_doc.FirstChildElement("ROWSET");
        if (!rowset) continue;
        // Iterate <ROW> children
        for (auto row = rowset->FirstChildElement("ROW"); row; row = row->NextSiblingElement("ROW")) {
            std::unordered_map<std::string, std::string> m;
            for (auto col = row->FirstChildElement(); col; col = col->NextSiblingElement()) {
                std::string full = col->Name();
                auto pos = full.find(':');
                std::string name = pos == std::string::npos ? full : full.substr(pos + 1);
                const char *text = col->GetText();
                std::string value = text ? text : "";
                cols.insert(name);
                m[name] = value;
            }
            rows_out.push_back(std::move(m));
        }
    }
    return rows_out;
}

//--------------------------------------------------------------------------------------------------
// 7) Bind callback: fetch once to infer schema, but don't emit data here
//--------------------------------------------------------------------------------------------------
unique_ptr<FunctionData> fuse_bind(ClientContext &ctx, TableFunctionBindInput &input,
                                   vector<LogicalType> &return_types,
                                   vector<string> &names) {
    auto bind = make_uniq<FusionBindData>();
    // extract parameters
    bind->endpoint = input.inputs[0].GetValue<string>();
    bind->user     = input.inputs[1].GetValue<string>();
    bind->pass     = input.inputs[2].GetValue<string>();
    bind->path     = input.inputs[3].GetValue<string>();
    bind->sql      = input.inputs[4].GetValue<string>();

    std::cerr << "[DEBUG] fuse_bind: endpoint=" << bind->endpoint
              << " user=" << bind->user
              << " reportPath=" << bind->path << std::endl;

    // fetch report
    auto soap_xml   = FetchSoap(bind->endpoint, bind->user, bind->pass, bind->path, bind->sql);

    std::cerr << "[DEBUG] fuse_bind: fetched SOAP length=" << soap_xml.size() << std::endl;
    // DEBUG: print raw SOAP XML
    std::cerr << "[DEBUG] Raw SOAP XML:\n" << soap_xml << std::endl;
    auto report_xml = ExtractReportXML(soap_xml);
    // DEBUG: print decoded report XML
    std::cerr << "[DEBUG] Raw Report XML (decoded):\n" << report_xml << std::endl;

    // parse rows and infer schema
    set<string> cols;
    bind->rows = ParseRows(report_xml, cols);

    std::cerr << "[DEBUG] fuse_bind: parsed " << bind->rows.size() << " rows, columns: ";
    for (auto &col : bind->columns) std::cerr << col << ",";
    std::cerr << std::endl;

    for (auto &col : cols) {
        bind->columns.push_back(col);
        names.push_back(col);
        return_types.push_back(LogicalType::VARCHAR);
    }
    return bind;
}

// Add init_local callback
unique_ptr<LocalTableFunctionState> fuse_init_local(ExecutionContext &ctx,
                                                       TableFunctionInitInput &input,
                                                       GlobalTableFunctionState *gstate) {
    return make_uniq<FusionLocalState>();
}

//--------------------------------------------------------------------------------------------------
// 8) Execute callback: emit chunk by chunk
//--------------------------------------------------------------------------------------------------
void fuse_func(ClientContext &ctx, TableFunctionInput &data, DataChunk &out) {
    auto &bind = data.bind_data->Cast<FusionBindData>();
    auto &lstate = data.local_state->Cast<FusionLocalState>();
    auto &rows = bind.rows;

    std::cerr << "[DEBUG] fuse_func: offset=" << lstate.offset
              << " rows_total=" << rows.size()
              << std::endl;

    idx_t total = rows.size();
    if (lstate.offset >= total) {
        out.SetCardinality(0);
        return;
    }
    idx_t to_emit = MinValue<idx_t>(STANDARD_VECTOR_SIZE, total - lstate.offset);

    std::cerr << "[DEBUG] fuse_func: emitting " << to_emit
              << " rows starting at " << lstate.offset << std::endl;

    out.SetCardinality(to_emit);
    for (idx_t r = 0; r < to_emit; r++) {
        auto &row = rows[lstate.offset + r];
        for (idx_t c = 0; c < bind.columns.size(); c++) {
            auto &vec = out.data[c];
            auto val = row.count(bind.columns[c]) ? row.at(bind.columns[c]) : "";
            FlatVector::GetData<string_t>(vec)[r] = StringVector::AddString(vec, val);
        }
    }
    lstate.offset += to_emit;
}

//--------------------------------------------------------------------------------------------------
// 9) Load into DuckDB
//--------------------------------------------------------------------------------------------------
namespace duckdb {

void OfquackExtension::Load(DuckDB &db) {
    auto &inst = *db.instance;
    TableFunctionSet tf("oracle_fusion_wsdl_query");
    tf.AddFunction(TableFunction(
        //"oracle_fusion_wsdl_query",
        {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR,
         LogicalType::VARCHAR, LogicalType::VARCHAR},
        fuse_func,
        fuse_bind,
        nullptr,         // no init_global
        fuse_init_local  // local state for offset
    ));
    ExtensionUtil::RegisterFunction(inst, tf);
}

std::string OfquackExtension::Name()    { return "ofquack"; }
std::string OfquackExtension::Version() const { return ""; }

} // namespace duckdb

extern "C" {

DUCKDB_EXTENSION_API void ofquack_init(DatabaseInstance &db) {
    // Initialize libcurl globally
    curl_global_init(CURL_GLOBAL_DEFAULT);
    DuckDB d(db);
    d.LoadExtension<OfquackExtension>();
}
DUCKDB_EXTENSION_API const char *ofquack_version() {
    return DuckDB::LibraryVersion();
}

DUCKDB_EXTENSION_API void ofquack_shutdown() {
    curl_global_cleanup();
}

} // extern "C"