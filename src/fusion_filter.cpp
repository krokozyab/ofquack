#include "ofquack/fusion_filter.hpp"

#include "duckdb/common/enums/expression_type.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/planner/expression/bound_comparison_expression.hpp"
#include "duckdb/planner/expression/bound_conjunction_expression.hpp"
#include "duckdb/planner/expression/bound_constant_expression.hpp"
#include "duckdb/planner/expression/bound_function_expression.hpp"
#include "duckdb/planner/expression/bound_operator_expression.hpp"
#include "duckdb/planner/expression/bound_reference_expression.hpp"
#include "duckdb/planner/filter/expression_filter.hpp"
#include "duckdb/planner/filter/table_filter_functions.hpp"
#include "duckdb/planner/table_filter_set.hpp"

namespace duckdb {

namespace {

//! Oracle rejects an IN list longer than this.
constexpr idx_t MAX_IN_LIST = 1000;

[[noreturn]] void Refuse(const string &what) {
	throw NotImplementedException(
	    "ofquack cannot push %s to Oracle Fusion without changing the result. "
	    "Run with SET fusion_scanner_filter_pushdown = false to filter in DuckDB instead.",
	    what);
}

string QuoteIdentifier(const string &name) {
	return KeywordHelper::WriteQuotedAndEscaped(name, '"');
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

// DuckDB 2.0 hands a scan one kind of filter: an ExpressionFilter wrapping a
// bound expression tree. The legacy filter classes still exist, but LogicalGet
// converts every one of them through ExpressionFilter::FromTableFilter before a
// scan sees it, so this is the only shape there is to translate:
//
//   col = C            BoundFunctionExpression whose GetExpressionType() is a
//                      COMPARE_*; operands via BoundComparisonExpression::Left/Right
//   col IS [NOT] NULL  BoundOperatorExpression(OPERATOR_IS_[NOT_]NULL), one child
//   col IN (C, ...)    BoundOperatorExpression(COMPARE_IN), children [col, C, C, ...]
//   a AND b / a OR b   BoundConjunctionExpression
//   optional(f)        BoundFunctionExpression named OptionalFilterScalarFun::NAME,
//                      the real predicate in its BindInfo()->child_filter_expr
//
// The column is a BoundReferenceExpression. A single-column filter refers to
// index 0; anything else is a predicate over several columns, which this
// translator does not attempt.

bool IsOptionalWrapper(const Expression &expression) {
	if (expression.GetExpressionClass() != ExpressionClass::BOUND_FUNCTION) {
		return false;
	}
	const auto &name = expression.Cast<BoundFunctionExpression>().Function().GetName();
	return name == OptionalFilterScalarFun::NAME || name == SelectivityOptionalFilterScalarFun::NAME;
}

//! The predicate an optional wrapper carries, or null when it carries none.
const Expression *OptionalChild(const Expression &expression) {
	const auto &function = expression.Cast<BoundFunctionExpression>();
	if (!function.BindInfo()) {
		return nullptr;
	}
	if (function.Function().GetName() == OptionalFilterScalarFun::NAME) {
		return function.BindInfo()->Cast<OptionalFilterFunctionData>().child_filter_expr.get();
	}
	return function.BindInfo()->Cast<SelectivityOptionalFilterFunctionData>().child_filter_expr.get();
}

void RequireColumnReference(const Expression &expression) {
	if (expression.GetExpressionClass() != ExpressionClass::BOUND_REF) {
		Refuse("a predicate whose subject is not the column itself");
	}
	if (expression.Cast<BoundReferenceExpression>().Index() != 0) {
		// A filter over several columns binds them as references 0, 1, ...;
		// this is handed one column and proves things about that column only.
		Refuse("a predicate over more than one column");
	}
}

const Value &RequireConstant(const Expression &expression) {
	if (expression.GetExpressionClass() != ExpressionClass::BOUND_CONSTANT) {
		Refuse("a comparison with something other than a constant");
	}
	return expression.Cast<BoundConstantExpression>().GetValue();
}

string TranslateExpression(const Expression &expression, const FusionColumn &column, const string &quoted_name);

string TranslateComparison(const BoundFunctionExpression &comparison, const FusionColumn &column,
                           const string &quoted_name) {
	// The planner puts the column on the left of a pushed filter. A constant on
	// the left would need the operator flipped, and nothing observed produces
	// that shape, so it is refused rather than guessed at.
	RequireColumnReference(BoundComparisonExpression::Left(comparison));
	const auto &constant = RequireConstant(BoundComparisonExpression::Right(comparison));
	return quoted_name + " " + ComparisonOperator(comparison.GetExpressionType(), column) + " " +
	       OracleLiteral(constant, column);
}

string TranslateExpression(const Expression &expression, const FusionColumn &column, const string &quoted_name) {
	if (IsOptionalWrapper(expression)) {
		// Reached only beneath a required predicate, where dropping it is not
		// allowed, so here it must translate or refuse like any other.
		const auto *child = OptionalChild(expression);
		if (!child) {
			Refuse("an optional filter");
		}
		return TranslateExpression(*child, column, quoted_name);
	}
	switch (expression.GetExpressionClass()) {
	case ExpressionClass::BOUND_FUNCTION:
		if (!BoundComparisonExpression::IsComparison(expression)) {
			// A dynamic or bloom filter is completed at run time from a join's
			// build side, so there is nothing to render at bind time at all.
			Refuse("a function call");
		}
		return TranslateComparison(expression.Cast<BoundFunctionExpression>(), column, quoted_name);
	case ExpressionClass::BOUND_OPERATOR: {
		const auto &op = expression.Cast<BoundOperatorExpression>();
		const auto &children = op.GetChildren();
		switch (op.GetExpressionType()) {
		case ExpressionType::OPERATOR_IS_NULL:
		case ExpressionType::OPERATOR_IS_NOT_NULL:
			if (children.size() != 1) {
				Refuse("a malformed null test");
			}
			RequireColumnReference(*children[0]);
			return quoted_name +
			       (op.GetExpressionType() == ExpressionType::OPERATOR_IS_NULL ? " IS NULL" : " IS NOT NULL");
		case ExpressionType::COMPARE_IN: {
			if (children.size() < 2) {
				Refuse("an empty IN list");
			}
			RequireColumnReference(*children[0]);
			const auto value_count = children.size() - 1;
			if (value_count > MAX_IN_LIST) {
				Refuse("an IN list of " + std::to_string(value_count) + " values (Oracle allows " +
				       std::to_string(MAX_IN_LIST) + ")");
			}
			string values;
			for (idx_t index = 1; index < children.size(); index++) {
				if (!values.empty()) {
					values += ", ";
				}
				// One untranslatable element refuses the whole list: applying
				// part of an IN would drop rows that belong in the result.
				values += OracleLiteral(RequireConstant(*children[index]), column);
			}
			return quoted_name + " IN (" + values + ")";
		}
		default:
			Refuse("operator " + ExpressionTypeToString(op.GetExpressionType()));
		}
	}
	case ExpressionClass::BOUND_CONJUNCTION: {
		const auto &conjunction = expression.Cast<BoundConjunctionExpression>();
		const char *joiner = conjunction.GetExpressionType() == ExpressionType::CONJUNCTION_AND ? " AND " : " OR ";
		string combined;
		for (const auto &child : conjunction.GetChildren()) {
			if (!combined.empty()) {
				combined += joiner;
			}
			combined += TranslateExpression(*child, column, quoted_name);
		}
		if (combined.empty()) {
			// It would silently become no predicate at all, and an empty OR is
			// false, not true.
			Refuse("an empty conjunction");
		}
		return "(" + combined + ")";
	}
	default:
		Refuse("expression class " + ExpressionClassToString(expression.GetExpressionClass()));
	}
}

//! An optional filter is a hint, not a requirement: DuckDB does not rely on it
//! being applied, so one that cannot be translated is simply dropped. Anything
//! else must translate or refuse.
bool TryTranslate(const TableFilter &filter, const FusionColumn &column, const string &quoted_name, string &out) {
	if (filter.filter_type != TableFilterType::EXPRESSION_FILTER) {
		// LogicalGet converts every legacy filter before a scan sees it, so one
		// arriving here is a planner path this code has not met.
		Refuse("filter kind " + std::to_string(static_cast<int>(filter.filter_type)));
	}
	const auto &expression = *filter.Cast<ExpressionFilter>().expr;
	if (!IsOptionalWrapper(expression)) {
		out = TranslateExpression(expression, column, quoted_name);
		return true;
	}
	const auto *child = OptionalChild(expression);
	if (!child) {
		return false;
	}
	try {
		out = TranslateExpression(*child, column, quoted_name);
		return true;
	} catch (const NotImplementedException &) {
		// Dropping an optional filter is allowed; refusing the query is not.
		return false;
	}
}

} // namespace

string BuildOracleWhereClause(const TableFilterSet &filters, const vector<FusionColumn> &columns,
                              const vector<column_t> &scanned_columns) {
	if (filters.HasMultiColumnFilters()) {
		// Each column of such a predicate is bound as its own reference; this
		// translator proves things about one column at a time.
		Refuse("a predicate over more than one column");
	}
	string predicate;
	for (const auto &entry : filters) {
		// The key indexes the projection, not the table.
		const auto projection = entry.GetIndex().GetIndex();
		if (projection >= scanned_columns.size()) {
			Refuse("a filter on a column this scan does not read");
		}
		const auto column_index = scanned_columns[projection];
		if (column_index >= columns.size()) {
			Refuse("a filter on a virtual column");
		}
		const auto &column = columns[column_index];
		if (!column.type_from_dictionary) {
			// The type came from looking at data, so Oracle's comparison and
			// DuckDB's need not agree on what the column even is.
			Refuse("a filter on a column whose type was inferred rather than read from the dictionary");
		}

		string translated;
		if (!TryTranslate(entry.Filter(), column, QuoteIdentifier(column.name), translated)) {
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
