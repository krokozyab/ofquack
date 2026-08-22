#pragma once

#include <string>

namespace ofquack {

//! Builds the SOAP 1.2 body for BI Publisher's runReport operation, carrying the
//! caller's SQL in the report's p_sql parameter.
//!
//! sizeOfDataChunkDownload is pinned to -1: BI Publisher's own chunking is not
//! used, so the whole result arrives in one response. Paging is done by
//! rewriting the SQL instead, which is the only mechanism the report exposes.
std::string BuildEnvelope(const std::string &sql, const std::string &report_path);

} // namespace ofquack
