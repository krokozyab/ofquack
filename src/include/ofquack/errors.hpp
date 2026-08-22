#pragma once

#include <stdexcept>
#include <string>

namespace ofquack {

//! Base for everything this layer throws, so the DuckDB adapter can turn the
//! whole family into one typed database error.
class FusionError : public std::runtime_error {
public:
	explicit FusionError(const std::string &message) : std::runtime_error(message) {
	}
};

//! The request failed in a way that another attempt might survive: a timeout, a
//! dropped connection, a 503.
class RetryableError : public FusionError {
public:
	explicit RetryableError(const std::string &message) : FusionError(message) {
	}
};

//! The request failed in a way that will fail again: bad SQL, a missing table,
//! a rejected password. Retrying only makes the user wait longer.
class PermanentError : public FusionError {
public:
	explicit PermanentError(const std::string &message) : FusionError(message) {
	}
};

//! Credentials were rejected. Never retried: repeating a bad password can lock
//! the account out, and it will not start working on the second try.
class AuthenticationError : public PermanentError {
public:
	explicit AuthenticationError(const std::string &message) : PermanentError(message) {
	}
};

//! A bearer token has expired. Distinct from AuthenticationError because it is
//! recoverable -- refresh the token and try once more.
class TokenExpiredError : public FusionError {
public:
	explicit TokenExpiredError(const std::string &message) : FusionError(message) {
	}
};

//! Too many consecutive failures against this host, so the request was not
//! even attempted.
class CircuitOpenError : public FusionError {
public:
	explicit CircuitOpenError(const std::string &message) : FusionError(message) {
	}
};

//! The caller asked to stop, or the deadline passed.
class CancelledError : public FusionError {
public:
	explicit CancelledError(const std::string &message) : FusionError(message) {
	}
};

} // namespace ofquack
