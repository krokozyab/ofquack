#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace ofquack {

//! Types this layer can infer. Kept independent of duckdb::LogicalType so the
//! inference stays testable without linking DuckDB.
enum class InferredType { VARCHAR, INTEGER, BIGINT, DECIMAL, DOUBLE, DATE, TIMESTAMP };

struct InferredColumn {
	InferredType type = InferredType::VARCHAR;
	//! Digits after the point, for DECIMAL. Zero otherwise.
	uint8_t scale = 0;
};

//! Number of leading rows examined. Everything after them is assumed to look
//! like them; a value that does not will be read back as NULL, which is why
//! the caller can turn inference off.
constexpr size_t TYPE_SAMPLE_ROWS = 20;

//! Guesses a column's type from sample values.
//!
//! Every value must fit for the guess to hold: one value that does not parse
//! drops the whole column to VARCHAR, since half a column of NULLs is worse
//! than a column of strings.
//!
//! Empty samples are skipped, and a column of nothing but empty values is
//! VARCHAR. Values with leading zeros stay VARCHAR too: '00123' is an account
//! code, and reading it as 123 loses information the user cannot recover.
InferredColumn InferColumnType(const std::vector<std::string> &samples);

} // namespace ofquack
