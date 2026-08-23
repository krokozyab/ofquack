#include "ofquack/oracle_type_map.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>

namespace ofquack {

namespace {

std::string UpperTrimmed(const std::string &text) {
	const auto first = text.find_first_not_of(" \t\r\n");
	if (first == std::string::npos) {
		return {};
	}
	const auto last = text.find_last_not_of(" \t\r\n");
	std::string result = text.substr(first, last - first + 1);
	for (auto &c : result) {
		c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
	}
	return result;
}

bool StartsWith(const std::string &text, const char *prefix) {
	const std::string needle = prefix;
	return text.size() >= needle.size() && text.compare(0, needle.size(), needle) == 0;
}

} // namespace

DictionaryColumnType MapOracleType(const std::string &type_name, int64_t precision, int64_t scale) {
	const auto type = UpperTrimmed(type_name);
	if (type.empty()) {
		return {};
	}

	if (StartsWith(type, "VARCHAR") || StartsWith(type, "NVARCHAR") || type == "CHAR" || type == "NCHAR" ||
	    type == "CLOB" || type == "NCLOB" || type == "LONG" || type == "C" || type == "V") {
		return {true, InferredType::VARCHAR, 0};
	}

	if (type == "NUMBER" || type == "FLOAT" || type == "INTEGER" || type == "BINARY_DOUBLE" ||
	    type == "BINARY_FLOAT" || type == "N") {
		if (scale == 0 && precision >= 1 && precision <= 9) {
			return {true, InferredType::INTEGER, 0};
		}
		if (scale == 0 && precision >= 10 && precision <= 18) {
			return {true, InferredType::BIGINT, 0};
		}
		// A NUMBER with no declared precision, or with a fractional part.
		// DECIMAL(38, s) is the widest Oracle can have meant.
		const auto effective_scale = static_cast<uint8_t>(std::min<int64_t>(std::max<int64_t>(scale, 0), 38));
		return {true, InferredType::DECIMAL, effective_scale};
	}

	// Oracle's DATE carries a time of day, so TIMESTAMP is the honest mapping;
	// DATE would silently truncate it.
	if (type == "DATE" || type == "D" || type == "T" || StartsWith(type, "TIMESTAMP")) {
		return {true, InferredType::TIMESTAMP, 0};
	}

	// RAW, BLOB, intervals, object types: not recognised, so the caller falls
	// back to inference rather than guessing wrong.
	return {};
}

bool IsSortableOracleType(const std::string &type_name) {
	auto upper = type_name;
	for (auto &c : upper) {
		c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
	}
	// Matched as prefixes: the dictionary spells them plain, but a synonym or a
	// vendor type can arrive as CLOB(4000) or NCLOB CHARACTER SET ...
	static const char *const UNSORTABLE[] = {"CLOB", "NCLOB", "BLOB", "BFILE", "LONG",
	                                         "RAW",  "XMLTYPE", "ANYDATA", "SDO_"};
	for (const auto *name : UNSORTABLE) {
		if (upper.compare(0, std::string(name).size(), name) == 0) {
			return false;
		}
	}
	// An unknown type is treated as sortable: the alternative is dropping
	// columns from the order for no reason, which weakens it for every type the
	// map has not learned yet.
	return true;
}

} // namespace ofquack
