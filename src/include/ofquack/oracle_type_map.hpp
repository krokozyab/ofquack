#pragma once

#include "ofquack/type_inference.hpp"

#include <cstdint>
#include <string>

namespace ofquack {

//! What an Oracle NUMBER with no declared precision or scale becomes.
//!
//! Fusion declares its amount columns that way, so this is not a corner case:
//! the dictionary says only "a number", and every choice from there loses
//! something. The mode is which loss the caller prefers.
enum class NumberMode {
	//! DOUBLE. Every value below 2^53 is exact and arithmetic just works; a
	//! wider integer identifier loses its low digits. The default, because an
	//! unconstrained NUMBER is nearly always a quantity rather than a key.
	DOUBLE,
	//! DECIMAL(38, 6). Exact to six decimal places -- enough for money and for
	//! most rates -- and anything finer is truncated.
	DECIMAL,
	//! VARCHAR. Loses nothing at all and is the only mode that can round-trip
	//! every value Oracle allows, at the cost of a column you cannot sum
	//! without casting it yourself.
	TEXT
};

//! Digits after the point under NumberMode::DECIMAL. Money needs two, exchange
//! rates and unit prices more; six covers both without spending the width an
//! unconstrained NUMBER might use on the integer side.
constexpr uint8_t UNCONSTRAINED_DECIMAL_SCALE = 6;

struct DictionaryColumnType {
	bool known = false;
	InferredType type = InferredType::VARCHAR;
	uint8_t scale = 0;
	//! True when the dictionary declared no precision or scale, so the type is
	//! this extension's choice rather than something Oracle stated. Under every
	//! mode but TEXT that choice can lose a value the column is allowed to hold.
	bool lossy = false;
};

//! Maps an Oracle dictionary type to the type a scan should present.
//!
//! `precision` and `scale` come from the dictionary rows as fetched, which
//! means from the *shifted* aliases: the column labelled DECIMAL_DIGITS holds
//! Oracle's data_precision and the one labelled NUM_PREC_RADIX holds its
//! data_scale. Callers pass them in their true meaning; the fetcher is what
//! un-shifts them.
//!
//! Returns `known = false` for a type this does not recognise, which leaves the
//! caller to fall back on inference from the data. FND's single-letter domain
//! codes (C, V, N, D, T) are recognised alongside the full Oracle names.
DictionaryColumnType MapOracleType(const std::string &type_name, int64_t precision, int64_t scale,
                                   NumberMode number_mode = NumberMode::DOUBLE);

//! False for the Oracle types that cannot appear in an ORDER BY: the large
//! object types, LONG, and the object types built on them. Sorting by one of
//! these is ORA-00932, so a statement paged by ordering on every column has to
//! leave them out.
bool IsSortableOracleType(const std::string &type_name);

} // namespace ofquack
