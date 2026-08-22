#pragma once

#include <string>

namespace ofquack {

//! Longest message DescribeFailure will return. A SOAP fault carrying a full
//! Java stack trace is otherwise several screens of noise.
constexpr size_t MAX_REPORTED_ERROR_LENGTH = 2000;

//! Extracts every "ORA-nnnnn: …" message from a blob of text, joined by "; ".
//! Empty if there are none.
std::string ExtractOracleErrors(const std::string &text);

//! Explains why a response is not a usable report, or returns an empty string
//! if nothing recognisable can be found.
//!
//! Handles the three shapes Fusion actually returns on failure: a SOAP 1.1
//! fault (faultstring), a SOAP 1.2 fault (Reason/Text) and an HTML error or
//! login page (title or h1). Oracle's own ORA- codes are preferred over the
//! wrapper text, since they say what really went wrong.
std::string DescribeFailure(const std::string &response);

} // namespace ofquack
