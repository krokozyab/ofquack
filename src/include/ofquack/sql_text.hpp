#pragma once

#include <cstddef>
#include <string>

namespace ofquack {

//! Removes comments and collapses runs of whitespace, leaving string literals
//! and quoted identifiers byte for byte intact.
//!
//! A single pass over the text with a state machine, not a regular expression:
//! the naive `\s+` replacement corrupts values, turning 'a   b' into 'a b'.
//!
//! Optimiser hints are kept. Oracle spells a hint `/*+ … */`, which is
//! lexically a block comment, so a comment stripper that does not special-case
//! it silently discards the plan the author asked for. The JDBC driver has that
//! bug; this does not.
std::string NormalizeSql(const std::string &sql);

//! Finds `keyword` outside string literals, quoted identifiers and comments,
//! matched case-insensitively and only at word boundaries.
//!
//! `SELECT 'OFFSET' FROM t` does not contain the keyword OFFSET by this
//! definition, which is the distinction a plain substring search misses.
//! Returns npos when absent.
size_t FindKeyword(const std::string &sql, const std::string &keyword, size_t from = 0);

//! True when the statement is a SELECT or a WITH clause feeding one, ignoring
//! leading whitespace and comments.
bool IsSelectStatement(const std::string &sql);

} // namespace ofquack
