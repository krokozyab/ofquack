#include "ofquack/type_inference.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>

namespace ofquack {

namespace {

bool IsDigit(char c) {
	return std::isdigit(static_cast<unsigned char>(c)) != 0;
}

bool AllDigits(const std::string &text, size_t from, size_t to) {
	if (from >= to) {
		return false;
	}
	for (size_t i = from; i < to; i++) {
		if (!IsDigit(text[i])) {
			return false;
		}
	}
	return true;
}

struct NumericShape {
	bool is_integer = false;
	bool is_decimal = false;
	size_t integer_digits = 0;
	uint8_t scale = 0;
};

//! Recognises the two numeric shapes dbms_xmlgen emits, and rejects anything
//! with a leading zero.
NumericShape ClassifyNumeric(const std::string &value) {
	NumericShape shape;
	size_t at = 0;
	if (at < value.size() && (value[at] == '-' || value[at] == '+')) {
		at++;
	}
	const auto digits_start = at;
	while (at < value.size() && IsDigit(value[at])) {
		at++;
	}
	const auto integer_digits = at - digits_start;
	if (integer_digits == 0) {
		return shape;
	}
	// "0" itself is a number; "0123" is an identifier that happens to be digits.
	const bool leading_zero = integer_digits > 1 && value[digits_start] == '0';
	if (leading_zero) {
		return shape;
	}

	if (at == value.size()) {
		shape.is_integer = true;
		shape.integer_digits = integer_digits;
		return shape;
	}
	if (value[at] != '.') {
		return shape;
	}
	const auto fraction_start = ++at;
	if (!AllDigits(value, fraction_start, value.size())) {
		return shape;
	}
	shape.is_decimal = true;
	shape.integer_digits = integer_digits;
	shape.scale = static_cast<uint8_t>(std::min<size_t>(value.size() - fraction_start, 38));
	return shape;
}

bool LooksLikeDate(const std::string &value) {
	// YYYY-MM-DD
	return value.size() == 10 && AllDigits(value, 0, 4) && value[4] == '-' && AllDigits(value, 5, 7) &&
	       value[7] == '-' && AllDigits(value, 8, 10);
}

bool LooksLikeTimestamp(const std::string &value) {
	// YYYY-MM-DD[T ]HH:MM:SS, with anything after the seconds tolerated.
	if (value.size() < 19 || !LooksLikeDate(value.substr(0, 10))) {
		return false;
	}
	if (value[10] != 'T' && value[10] != ' ') {
		return false;
	}
	return AllDigits(value, 11, 13) && value[13] == ':' && AllDigits(value, 14, 16) && value[16] == ':' &&
	       AllDigits(value, 17, 19);
}

} // namespace

InferredColumn InferColumnType(const std::vector<std::string> &samples) {
	bool saw_value = false;
	bool all_integer = true;
	bool all_bigint = true;
	bool all_decimal = true;
	bool all_date = true;
	bool all_timestamp = true;
	uint8_t max_scale = 0;

	for (const auto &value : samples) {
		if (value.empty()) {
			continue; // an empty value fits any type
		}
		saw_value = true;

		const auto numeric = ClassifyNumeric(value);
		// Nine digits always fit INT32; ten to eighteen always fit INT64.
		all_integer = all_integer && numeric.is_integer && numeric.integer_digits <= 9;
		all_bigint = all_bigint && numeric.is_integer && numeric.integer_digits <= 18;
		all_decimal = all_decimal && (numeric.is_decimal || numeric.is_integer);
		if (numeric.is_decimal) {
			max_scale = std::max(max_scale, numeric.scale);
		}

		all_date = all_date && LooksLikeDate(value);
		all_timestamp = all_timestamp && LooksLikeTimestamp(value);

		if (!all_integer && !all_bigint && !all_decimal && !all_date && !all_timestamp) {
			break; // nothing left to narrow
		}
	}

	if (!saw_value) {
		return {InferredType::VARCHAR, 0};
	}
	// Narrowest first, so a column of small integers is not widened to DECIMAL.
	if (all_integer) {
		return {InferredType::INTEGER, 0};
	}
	if (all_bigint) {
		return {InferredType::BIGINT, 0};
	}
	if (all_decimal) {
		return {InferredType::DECIMAL, max_scale};
	}
	// Checked after the numeric shapes: a date can never look like a number.
	if (all_timestamp) {
		return {InferredType::TIMESTAMP, 0};
	}
	if (all_date) {
		return {InferredType::DATE, 0};
	}
	return {InferredType::VARCHAR, 0};
}

} // namespace ofquack
