#pragma once

// Stable codes for what went wrong, for a program that acts on the kind of
// failure rather than on its wording. A message is written for a person and
// changes when it can be said better; a code does not change.
//
// The code rides on the DuckDB exception, in its extra_info under KEY, so the
// message stays what a person reads and DuckDB prints it as before:
//
//   const auto &info = error_data.ExtraInfo();
//   const auto code = info.find(ofquack::error_code::KEY);
//
// Cancellation has no code: it is an InterruptException, a type of its own. An
// error without a code is one these do not cover; its type still says which
// side it came from.
//
// No DuckDB here, so a caller can include it on its own.

namespace ofquack {
namespace error_code {

constexpr const char *KEY = "ofquack_error";

//! Fusion refused the username and password. Sending them again is refused
//! again, and counts towards locking the account. InvalidInputException.
constexpr const char *CREDENTIALS_REJECTED = "CREDENTIALS_REJECTED";
//! The secret has no username, so there was nothing to send.
//! InvalidInputException.
constexpr const char *CREDENTIALS_MISSING = "CREDENTIALS_MISSING";
//! No usable sign-in: no token, an expired or refused one, or a browser sign-in
//! that did not finish. Signing in again is the remedy. InvalidInputException,
//! or IOException for a token Fusion refused and a sign-in that did not finish.
constexpr const char *NOT_SIGNED_IN = "NOT_SIGNED_IN";
//! Oracle understood the statement and refused it: an ORA- error. IOException.
constexpr const char *QUERY_REJECTED = "QUERY_REJECTED";
//! The statement ran and returned no rows, so the result has no columns.
//! IOException.
constexpr const char *NO_ROWS = "NO_ROWS";
//! Fusion could not be reached or did not answer usably: the network, an HTTP
//! error, a response that is not a report, the circuit breaker. IOException.
constexpr const char *UNAVAILABLE = "UNAVAILABLE";

} // namespace error_code
} // namespace ofquack
