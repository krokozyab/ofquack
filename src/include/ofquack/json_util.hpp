#pragma once

#include <string>
#include <vector>

namespace ofquack {
namespace json {

//! Just enough JSON reading for the Chrome debugging protocol.
//!
//! The messages involved are small, flat and produced by Chrome, and the fields
//! wanted from them are a handful of strings and one integer. Field lookup is
//! by name anywhere in the document, which is adequate precisely because these
//! payloads are not nested in interesting ways -- do not reuse this for
//! anything where two fields could share a name at different depths.

//! Value of the first `"name": "…"` in the document, unescaped. Empty if absent
//! or not a string.
std::string StringField(const std::string &document, const std::string &name);

//! Value of the first `"name": <number>`. Zero if absent or not a number.
int64_t IntegerField(const std::string &document, const std::string &name);

//! Splits a top-level JSON array into its elements, as raw text.
std::vector<std::string> ParseArray(const std::string &document);

//! Renders `text` as a JSON string literal, quotes included.
std::string QuoteString(const std::string &text);

} // namespace json
} // namespace ofquack
