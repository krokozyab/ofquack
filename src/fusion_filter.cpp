#include "ofquack/fusion_filter.hpp"

#include "duckdb/common/enums/expression_type.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/planner/filter/conjunction_filter.hpp"
#include "duckdb/planner/filter/constant_filter.hpp"
#include "duckdb/planner/filter/in_filter.hpp"
#include "duckdb/planner/filter/null_filter.hpp"
#include "duckdb/planner/filter/optional_filter.hpp"

namespace duckdb {

namespace {

//! Oracle rejects an IN list longer than this.
constexpr idx_t MAX_IN_LIST = 1000;

[[noreturn]] void Refuse(const string &what) {
	throw NotImplementedException(
	    "ofquack cannot push %s to Oracle Fusion without changing the result. "
	    "Run with SET ofquack_filter_pushdown = false to filter in DuckDB instead.",
	    what);
}

string QuoteIdentifier(const string &name) {
	return KeywordHelper::WriteQuoted(name, '"');
}

bool IsTextType(const LogicalType &type) {
	return type.id() == LogicalTypeId::VARCHAR;
}

bool IsNumericType(const LogicalType &type) {
	switch (type.id()) {
	case LogicalTypeId::TINYINT:
	case LogicalTypeId::SMALLINT:
	case LogicalTypeId::INTEGER:
	case LogicalTypeId::BIGINT:
	case LogicalTypeId::HUGEINT:
	case LogicalTypeId::UTINYINT:
	case LogicalTypeId::USMALLINT:
	case LogicalTypeId::UINTEGER:
	case LogicalTypeId::UBIGINT:
	case LogicalTypeId::FLOAT:
	case LogicalTypeId::DOUBLE:
	case LogicalTypeId::DECIMAL:
		return true;
	default:
		return false;
	}
}

//! Renders a constant as an Oracle literal, refusing anything whose meaning
//! would depend on the server's session settings.
string OracleLiteral(const Value &value, const FusionColumn &column) {
	if (value.IsNull()) {
		// Should have been folded away before reaching a scan; comparing to
		// NULL is never true, and emitting it would look like a real predicate.
		Refuse("a comparison with NULL");
	}

	if (IsNumericType(column.type)) {
		if (!IsNumericType(value.type())) {
			Refuse("a non-numeric constant compared with a numeric column");
		}
		return value.ToString();
	}

	if (IsTextType(column.type)) {
		if (value.type().id() != LogicalTypeId::VARCHAR) {
			Refuse("a non-text constant compared with a text column");
		}
		const auto text = value.ToString();
		if (text.empty()) {
			// Oracle stores '' as NULL, so col = '' matches nothing there while
			// it matches empty strings in DuckDB. Different predicates.
			Refuse("a comparison with the empty string");
		}
		return "'" + StringUtil::Replace(text, "'", "''") + "'";
	}

	if (column.type.id() == LogicalTypeId::DATE) {
		if (value.type().id() != LogicalTypeId::DATE) {
			Refuse("a non-date constant compared with a date column");
		}
		// The format is spelled out so NLS_DATE_FORMAT cannot reinterpret it.
		return "TO_DATE('" + value.ToString() + "', 'YYYY-MM-DD')";
	}

	if (column.type.id() == LogicalTypeId::TIMESTAMP) {
		if (value.type().id() != LogicalTypeId::TIMESTAMP) {
			Refuse("a non-timestamp constant compared with a timestamp column");
		}
		auto text = value.ToString();
		// DuckDB prints 'YYYY-MM-DD HH:MM:SS[.ffffff]'.
		return "TO_TIMESTAMP('" + text + "', 'YYYY-MM-DD HH24:MI:SS.FF')";
	}

	Refuse("a constant of type " + column.type.ToString());
}

string ComparisonOperator(ExpressionType comparison, const FusionColumn &column) {
	switch (comparison) {
	case ExpressionType::COMPARE_EQUAL:
		return "=";
	case ExpressionType::COMPARE_NOTEQUAL:
		return "<>";
	case ExpressionType::COMPARE_LESSTHAN:
	case ExpressionType::COMPARE_LESSTHANOREQUALTO:
	case ExpressionType::COMPARE_GREATERTHAN:
	case ExpressionType::COMPARE_GREATERTHANOREQUALTO:
		if (IsTextType(column.type)) {
			// Ordering of text depends on NLS_SORT and NLS_COMP, which this
			// connection does not negotiate; equality does not.
			Refuse("an ordered comparison on a text column");
		}
		switch (comparison) {
		case ExpressionType::COMPARE_LESSTHAN:
			return "<";
		case ExpressionType::COMPARE_LESSTHANOREQUALTO:
			return "<=";
		case ExpressionType::COMPARE_GREATERTHAN:
			return ">";
		default:
			return ">=";
		}
	default:
		Refuse("comparison " + ExpressionTypeToString(comparison));
	}
}

string TranslateFilter(const TableFilter &filter, const FusionColumn &column, const string &quoted_name);

//! An optional filter is a hint, not a requirement: DuckDB does not rely on it
//! being applied, so one that cannot be translated is simply dropped.
bool TryTranslateOptional(const TableFilter &filter, const FusionColumn &column, const string &quoted_name,
                          string &out) {
	const auto &optional = filter.Cast<OptionalFilter>();
	if (!optional.child_filter) {
		return false;
	}
	try {
		out = TranslateFilter(*optional.child_filter, column, quoted_name);
		return true;
	} catch (const NotImplementedException &) {
		return false;
	}
}

string TranslateConjunction(const vector<unique_ptr<TableFilter>> &children, const FusionColumn &column,
                            const string &quoted_name, const char *joiner) {
	string combined;
	for (const auto &child : children) {
		const auto translated = TranslateFilter(*child, column, quoted_name);
		if (!combined.empty()) {
			combined += joiner;
		}
		combined += translated;
	}
	return combined.empty() ? combined : "(" + combined + ")";
}

string TranslateFilter(const TableFilter &filter, const FusionColumn &column, const string &quoted_name) {
	switch (filter.filter_type) {
	case TableFilterType::IS_NULL:
		return quoted_name + " IS NULL";
	case TableFilterType::IS_NOT_NULL:
		return quoted_name + " IS NOT NULL";
	case TableFilterType::CONSTANT_COMPARISON: {
		const auto &comparison = filter.Cast<ConstantFilter>();
		return quoted_name + " " + ComparisonOperator(comparison.comparison_type, column) + " " +
		       OracleLiteral(comparison.constant, column);
	}
	case TableFilterType::IN_FILTER: {
		const auto &in_filter = filter.Cast<InFilter>();
		if (in_filter.values.size() > MAX_IN_LIST) {
			Refuse("an IN list of " + std::to_string(in_filter.values.size()) + " values (Oracle allows " +
			       std::to_string(MAX_IN_LIST) + ")");
		}
		string values;
		for (const auto &value : in_filter.values) {
			if (!values.empty()) {
				values += ", ";
			}
			// One untranslatable element refuses the whole list: applying part
			// of an IN would drop rows that belong in the result.
			values += OracleLiteral(value, column);
		}
		if (values.empty()) {
			Refuse("an empty IN list");
		}
		return quoted_name + " IN (" + values + ")";
	}
	case TableFilterType::CONJUNCTION_AND:
		return TranslateConjunction(filter.Cast<ConjunctionAndFilter>().child_filters, column, quoted_name, " AND ");
	case TableFilterType::CONJUNCTION_OR:
		return TranslateConjunction(filter.Cast<ConjunctionOrFilter>().child_filters, column, quoted_name, " OR ");
	case TableFilterType::OPTIONAL_FILTER: {
		string translated;
		if (!TryTranslateOptional(filter, column, quoted_name, translated)) {
			Refuse("an optional filter");
		}
		return translated;
	}
	default:
		// DYNAMIC_FILTER and BLOOM_FILTER are completed at run time from a join
		// build side, so there is nothing to render at bind time at all.
		Refuse("filter kind " + std::to_string(static_cast<int>(filter.filter_type)));
	}
}

} // namespace

string BuildOracleWhereClause(const TableFilterSet &filters, const vector<FusionColumn> &columns,
                              const vector<column_t> &scanned_columns) {
	string predicate;
	for (const auto &entry : filters.filters) {
		// The key indexes the projection, not the table.
		if (entry.first >= scanned_columns.size()) {
			Refuse("a filter on a column this scan does not read");
		}
		const auto column_index = scanned_columns[entry.first];
		if (column_index >= columns.size()) {
			Refuse("a filter on a virtual column");
		}
		const auto &column = columns[column_index];
		if (!column.type_from_dictionary) {
			// The type came from looking at data, so Oracle's comparison and
			// DuckDB's need not agree on what the column even is.
			Refuse("a filter on a column whose type was inferred rather than read from the dictionary");
		}

		const auto quoted_name = QuoteIdentifier(column.name);
		string translated;
		if (entry.second->filter_type == TableFilterType::OPTIONAL_FILTER) {
			// Dropping an optional filter is allowed; refusing the query is not.
			if (!TryTranslateOptional(*entry.second, column, quoted_name, translated)) {
				continue;
			}
		} else {
			translated = TranslateFilter(*entry.second, column, quoted_name);
		}
		if (translated.empty()) {
			continue;
		}
		if (!predicate.empty()) {
			predicate += " AND ";
		}
		predicate += translated;
	}
	return predicate;
}

} // namespace duckdb
