#pragma once

#include <string>

namespace ofquack {

//! Makes `text` safe to place inside a CDATA section.
//!
//! CDATA has exactly one escape problem: the sequence "]]>" ends the section
//! early, so a query containing it would otherwise inject the rest of itself
//! into the SOAP envelope as markup. The fix is to close and reopen the
//! section around it, which the XML parser rejoins into the original bytes.
std::string EscapeCdata(const std::string &text);

//! Builds the SOAP 1.2 body for BI Publisher's runReport operation, carrying the
//! caller's SQL in the report's p_sql parameter.
//!
//! sizeOfDataChunkDownload is pinned to -1: BI Publisher's own chunking is not
//! used, so the whole result arrives in one response. Paging is done by
//! rewriting the SQL instead, which is the only mechanism the report exposes.
std::string BuildEnvelope(const std::string &sql, const std::string &report_path);

} // namespace ofquack
