#pragma once

#include "ofquack/type_inference.hpp"

#include <cstdint>
#include <string>

namespace ofquack {

struct DictionaryColumnType {
	bool known = false;
	InferredType type = InferredType::VARCHAR;
	uint8_t scale = 0;
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
DictionaryColumnType MapOracleType(const std::string &type_name, int64_t precision, int64_t scale);

//! False for the Oracle types that cannot appear in an ORDER BY: the large
//! object types, LONG, and the object types built on them. Sorting by one of
//! these is ORA-00932, so a statement paged by ordering on every column has to
//! leave them out.
bool IsSortableOracleType(const std::string &type_name);

} // namespace ofquack
