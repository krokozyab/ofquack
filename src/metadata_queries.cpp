#include "ofquack/metadata_queries.hpp"

#include <cctype>
#include <cstdint>
#include <sstream>

namespace ofquack {
namespace metadata {

namespace {

//! java.sql.Types.VARCHAR, which the JDBC driver interpolated here. Kept as the
//! literal it produced so the statements match what Fusion has been serving.
constexpr int JDBC_VARCHAR = 12;
//! DatabaseMetaData.tableIndexOther.
constexpr int JDBC_INDEX_OTHER = 3;

std::string Upper(const std::string &text) {
	std::string upper;
	upper.reserve(text.size());
	for (const char c : text) {
		upper.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
	}
	return upper;
}

std::string JoinQuoted(const std::vector<std::string> &values) {
	std::string joined;
	for (const auto &value : values) {
		if (!joined.empty()) {
			joined += ",";
		}
		joined += "'" + QuoteLiteral(Upper(value)) + "'";
	}
	return joined;
}

//! TABLE_IDs are numeric and come from our own cache, so they are emitted
//! unquoted -- but still validated, since a non-numeric one would be
//! concatenated straight into the statement.
std::string JoinNumeric(const std::vector<std::string> &values) {
	std::string joined;
	for (const auto &value : values) {
		bool numeric = !value.empty();
		for (const char c : value) {
			numeric = numeric && std::isdigit(static_cast<unsigned char>(c));
		}
		if (!numeric) {
			continue;
		}
		if (!joined.empty()) {
			joined += ",";
		}
		joined += value;
	}
	return joined;
}

} // namespace

std::string QuoteLiteral(const std::string &value) {
	std::string quoted;
	quoted.reserve(value.size());
	for (const char c : value) {
		if (c == '\'') {
			quoted.push_back('\'');
		}
		quoted.push_back(c);
	}
	return quoted;
}

std::string PaginateByOffset(const std::string &base_sql, uint64_t offset, uint64_t page_size) {
	// Appended, not wrapped: every statement here ends in ORDER BY, which is
	// exactly where the row-limiting clause belongs.
	std::ostringstream oss;
	oss << base_sql << " OFFSET " << offset << " ROWS FETCH NEXT " << page_size << " ROWS ONLY";
	return oss.str();
}

std::string TablesAfter(const std::vector<std::string> &types, const std::string &after_name,
                        const std::string &after_type, uint64_t page_size) {
	const auto type_list = types.empty() ? std::string("'TABLE','VIEW'") : JoinQuoted(types);
	std::ostringstream oss;
	oss << "SELECT CAST(NULL AS VARCHAR2(1)) AS TABLE_CAT,"
	    << " '" << SCHEMA << "' AS TABLE_SCHEM,"
	    << " t.table_name, t.table_type,"
	    << " t.description AS REMARKS,"
	    << " t.table_id AS TABLE_ID"
	    << " FROM (SELECT view_id AS table_id, view_name AS table_name, 'VIEW' AS table_type, description"
	    << " FROM FND_VIEWS"
	    << " UNION ALL"
	    << " SELECT table_id, table_name, 'TABLE' AS table_type, description"
	    << " FROM FND_TABLES) t"
	    << " WHERE t.table_type IN (" << type_list << ")";

	if (!after_name.empty()) {
		// Ordered by (name, type), so the seek has to compare the pair. Oracle
		// has no row-value comparison outside IN, hence the expanded form.
		const auto name = QuoteLiteral(after_name);
		const auto type = QuoteLiteral(after_type);
		oss << " AND (t.table_name > '" << name << "'"
		    << " OR (t.table_name = '" << name << "' AND t.table_type > '" << type << "'))";
	}

	oss << " ORDER BY t.table_name, t.table_type"
	    << " FETCH FIRST " << page_size << " ROWS ONLY";
	return oss.str();
}

std::string TableCount(const std::vector<std::string> &types) {
	const auto type_list = types.empty() ? std::string("'TABLE','VIEW'") : JoinQuoted(types);
	std::ostringstream oss;
	// Distinct by name, because the listing this is compared against collapses a
	// name that exists as both a table and a view onto one entry. Counting rows
	// would exceed a complete listing by however many names overlap, and every
	// complete listing would then be reported as short.
	oss << "SELECT COUNT(DISTINCT UPPER(t.table_name)) AS TABLE_COUNT FROM ("
	    << "SELECT view_name AS table_name, 'VIEW' AS table_type FROM FND_VIEWS"
	    << " UNION ALL"
	    << " SELECT table_name, 'TABLE' AS table_type FROM FND_TABLES) t"
	    << " WHERE t.table_type IN (" << type_list << ")";
	return oss.str();
}

std::string ColumnsByTableIds(const std::vector<std::string> &table_ids) {
	std::ostringstream oss;
	oss << "SELECT NULL AS TABLE_CAT,"
	    << " '" << SCHEMA << "' AS TABLE_SCHEM,"
	    << " t.table_name AS TABLE_NAME,"
	    // user_column_name is the display name and is not always populated;
	    // falling back to the physical name keeps a table from arriving with
	    // no columns at all, which is indistinguishable from not existing.
	    << " COALESCE(c.user_column_name, c.column_name) AS COLUMN_NAME,"
	    << " " << JDBC_VARCHAR << " AS DATA_TYPE,"
	    << " COALESCE(c.column_type, c.domain_code) AS TYPE_NAME,"
	    << " c.width AS COLUMN_SIZE,"
	    // Shifted aliases, deliberately: see the header. DECIMAL_DIGITS carries
	    // the precision and NUM_PREC_RADIX the scale, the same way round as the
	    // view query -- this one used to put the scale in DECIMAL_DIGITS and the
	    // literal radix 10 in NUM_PREC_RADIX, so FND's own NUMBER(18,0) reached
	    // the mapper as precision 0, scale 10 and became DECIMAL(38,10).
	    << " c.\"PRECISION\" AS DECIMAL_DIGITS,"
	    << " c.\"SCALE\" AS NUM_PREC_RADIX,"
	    << " CASE WHEN c.null_allowed_flag = 'Y' THEN 1 ELSE 0 END AS NULLABLE,"
	    << " COALESCE(c.column_sequence, c.column_id) AS ORDINAL_POSITION,"
	    << " c.description AS REMARKS,"
	    << " c.table_id AS TABLE_ID"
	    << " FROM FND_COLUMNS c"
	    << " JOIN FND_TABLES t ON c.table_id = t.table_id"
	    << " WHERE c.table_id IN (" << JoinNumeric(table_ids) << ")"
	    << " ORDER BY c.table_id, COALESCE(c.column_sequence, c.column_id)";
	return oss.str();
}

std::string ColumnsOfViews(const std::string &table_name) {
	std::ostringstream oss;
	oss << "SELECT NULL AS TABLE_CAT,"
	    << " owner AS TABLE_SCHEM,"
	    << " table_name AS TABLE_NAME,"
	    << " column_name AS COLUMN_NAME,"
	    << " " << JDBC_VARCHAR << " AS DATA_TYPE,"
	    << " data_type AS TYPE_NAME,"
	    << " data_length AS COLUMN_SIZE,"
	    // Shifted aliases, deliberately: see the header.
	    << " data_precision AS DECIMAL_DIGITS,"
	    << " data_scale AS NUM_PREC_RADIX,"
	    << " CASE WHEN nullable = 'Y' THEN 1 ELSE 0 END AS NULLABLE,"
	    << " column_id AS ORDINAL_POSITION"
	    << " FROM all_tab_columns"
	    << " WHERE owner = '" << SCHEMA << "'"
	    // Oracle dictionary object names are stored in upper case. Keep the
	    // indexed column bare: this lookup is on the hot path while views warm.
	    << " AND table_name = '" << QuoteLiteral(Upper(table_name)) << "'"
	    << " ORDER BY owner, table_name, column_id";
	return oss.str();
}

std::string PrimaryKeys(const std::string &table_name) {
	std::ostringstream oss;
	oss << "SELECT NULL AS TABLE_CAT,"
	    << " c.owner AS TABLE_SCHEM,"
	    << " c.table_name AS TABLE_NAME,"
	    << " cc.column_name AS COLUMN_NAME,"
	    << " cc.position AS KEY_SEQ,"
	    << " c.constraint_name AS PK_NAME"
	    << " FROM all_constraints c"
	    << " JOIN all_cons_columns cc ON c.constraint_name = cc.constraint_name"
	    << " AND c.owner = cc.owner AND c.table_name = cc.table_name"
	    << " WHERE c.constraint_type = 'P'"
	    << " AND c.owner = '" << SCHEMA << "'"
	    // Bare column, upper-cased value: Oracle stores dictionary object names in
	    // upper case, and wrapping the column loses the index on it.
	    << " AND c.table_name = '" << QuoteLiteral(Upper(table_name)) << "'"
	    << " ORDER BY c.owner, c.table_name, cc.position";
	return oss.str();
}

std::string ForeignKeys(const std::string &table_name) {
	std::ostringstream oss;
	oss << "SELECT NULL AS PKTABLE_CAT,"
	    << " r.owner AS PKTABLE_SCHEM, r.table_name AS PKTABLE_NAME, rc.column_name AS PKCOLUMN_NAME,"
	    << " NULL AS FKTABLE_CAT,"
	    << " c.owner AS FKTABLE_SCHEM, c.table_name AS FKTABLE_NAME, cc.column_name AS FKCOLUMN_NAME,"
	    << " cc.position AS KEY_SEQ,"
	    << " CASE c.delete_rule WHEN 'CASCADE' THEN 0 WHEN 'SET NULL' THEN 2 ELSE 1 END AS UPDATE_RULE,"
	    << " CASE c.delete_rule WHEN 'CASCADE' THEN 0 WHEN 'SET NULL' THEN 2 ELSE 1 END AS DELETE_RULE,"
	    << " c.constraint_name AS FK_NAME, r.constraint_name AS PK_NAME, 7 AS DEFERRABILITY"
	    << " FROM all_constraints c"
	    << " JOIN all_cons_columns cc ON c.constraint_name = cc.constraint_name AND c.owner = cc.owner"
	    << " JOIN all_constraints r ON c.r_constraint_name = r.constraint_name AND c.r_owner = r.owner"
	    << " JOIN all_cons_columns rc ON r.constraint_name = rc.constraint_name AND r.owner = rc.owner"
	    << " WHERE c.constraint_type = 'R'"
	    << " AND cc.position = rc.position"
	    << " AND c.owner = '" << SCHEMA << "'"
	    // Bare column, upper-cased value: Oracle stores dictionary object names in
	    // upper case, and wrapping the column loses the index on it.
	    << " AND c.table_name = '" << QuoteLiteral(Upper(table_name)) << "'"
	    << " ORDER BY c.owner, c.table_name, c.constraint_name, cc.position";
	return oss.str();
}

std::string Indexes(const std::string &table_name, bool unique_only) {
	std::ostringstream oss;
	oss << "SELECT NULL AS TABLE_CAT,"
	    << " idx.owner AS TABLE_SCHEM, idx.table_name AS TABLE_NAME,"
	    << " CASE WHEN idx.uniqueness = 'UNIQUE' THEN '0' ELSE '1' END AS NON_UNIQUE,"
	    << " NULL AS INDEX_QUALIFIER, idx.index_name AS INDEX_NAME,"
	    << " '" << JDBC_INDEX_OTHER << "' AS TYPE,"
	    << " ic.column_position AS ORDINAL_POSITION, ic.column_name AS COLUMN_NAME,"
	    << " CASE WHEN ic.descend = 'ASC' THEN 'A' WHEN ic.descend = 'DESC' THEN 'D' ELSE NULL END AS ASC_OR_DESC,"
	    << " NULL AS CARDINALITY, NULL AS PAGES, NULL AS FILTER_CONDITION"
	    << " FROM all_indexes idx"
	    << " JOIN all_ind_columns ic ON ic.index_owner = idx.owner AND ic.index_name = idx.index_name"
	    << " WHERE idx.owner = '" << SCHEMA << "'"
	    // Bare column, upper-cased value: Oracle stores dictionary object names in
	    // upper case, and wrapping the column loses the index on it.
	    << " AND idx.table_name = '" << QuoteLiteral(Upper(table_name)) << "'";
	if (unique_only) {
		oss << " AND idx.uniqueness = 'UNIQUE'";
	}
	oss << " ORDER BY idx.index_name, ic.column_position";
	return oss.str();
}

} // namespace metadata
} // namespace ofquack
