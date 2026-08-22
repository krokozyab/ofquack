#include "ofquack/metadata_fetch.hpp"

#include "ofquack/error_decoder.hpp"
#include "ofquack/errors.hpp"
#include "ofquack/metadata_queries.hpp"
#include "ofquack/xml_report.hpp"

#include <algorithm>
#include <cctype>
#include <unordered_map>
#include <unordered_set>

namespace ofquack {

namespace {

//! Upper bound on how many dictionary rows one listing may return, as a guard
//! against a paging loop that never terminates.
constexpr size_t MAX_METADATA_ROWS = 500000;

std::string Upper(const std::string &text) {
	std::string upper;
	upper.reserve(text.size());
	for (const char c : text) {
		upper.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
	}
	return upper;
}

std::string Trim(const std::string &text) {
	const auto first = text.find_first_not_of(" \t\r\n");
	if (first == std::string::npos) {
		return {};
	}
	const auto last = text.find_last_not_of(" \t\r\n");
	return text.substr(first, last - first + 1);
}

//! Reads a field by name, tolerating either case.
//!
//! dbms_xmlgen upper-cases element names, but the JDBC driver lower-cased some
//! result sets and not others, and the two conventions leaked into its cache.
//! Accepting both here means the case a response happens to use never matters.
std::string Field(const ReportRow &row, const std::string &name) {
	const auto upper = row.find(Upper(name));
	if (upper != row.end()) {
		return Trim(upper->second);
	}
	std::string lower = name;
	for (auto &c : lower) {
		c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	}
	const auto found = row.find(lower);
	return found == row.end() ? std::string() : Trim(found->second);
}

int64_t IntField(const ReportRow &row, const std::string &name, int64_t fallback = 0) {
	const auto text = Field(row, name);
	if (text.empty()) {
		return fallback;
	}
	try {
		return std::stoll(text);
	} catch (const std::exception &) {
		return fallback;
	}
}

//! Runs one statement and returns its rows.
//!
//! The parse errors are turned into something readable here rather than left
//! to escape. "Missing SOAP Envelope" is true but useless: it describes the
//! shape of a response without saying what the response was, and the answer is
//! usually visible in the first line of it.
std::vector<ReportRow> Query(FusionTransport &transport, const RequestContext &context, const std::string &sql) {
	const auto response = transport.Execute(sql, context);
	try {
		return ParseRows(ExtractReportXML(response)).rows;
	} catch (const std::runtime_error &parse_error) {
		const auto described = DescribeFailure(response);
		if (!described.empty()) {
			throw PermanentError("Oracle Fusion rejected a metadata query: " + described + "\nSQL: " + sql);
		}
		// Nothing recognisable: show the start of what did arrive, which is
		// how a sign-in page or a proxy notice announces itself.
		auto preview = response.substr(0, 300);
		for (auto &c : preview) {
			if (c == '\n' || c == '\r' || c == '\t') {
				c = ' ';
			}
		}
		throw PermanentError("Could not read the response to a metadata query (" + std::string(parse_error.what()) +
		                     ").\nThe response began: " + (preview.empty() ? "<empty>" : preview) + "\nSQL: " + sql);
	}
}

//! Runs a statement page by page until a short page arrives.
std::vector<ReportRow> QueryPaged(FusionTransport &transport, const RequestContext &context,
                                  const std::string &base_sql) {
	std::vector<ReportRow> all;
	uint64_t offset = 0;
	for (;;) {
		auto page = Query(transport, context, metadata::PaginateByRownum(base_sql, offset));
		const auto page_size = page.size();
		for (auto &row : page) {
			// The wrapper adds RN; it is an artefact of paging, not data.
			row.erase("RN");
			row.erase("rn");
			all.push_back(std::move(row));
		}
		// Stop on an empty page, not on a short one. BI Publisher truncates a
		// response without saying so, and a truncated page looks exactly like
		// the last one -- which silently cut the table list off partway
		// through the alphabet. The cost of being right is one extra request
		// at the end.
		if (page_size == 0) {
			return all;
		}
		offset += page_size;
		// A server that keeps returning rows without advancing would loop for
		// ever; the dictionary is large but finite.
		if (all.size() > MAX_METADATA_ROWS) {
			throw PermanentError("Oracle Fusion returned more than " + std::to_string(MAX_METADATA_ROWS) +
			                     " dictionary rows without ending; giving up rather than looping");
		}
	}
}

//! TABLE beats VIEW beats SYNONYM when one name arrives as more than one kind.
int TypePriority(const std::string &type) {
	const auto upper = Upper(type);
	if (upper == "TABLE") {
		return 1;
	}
	if (upper == "VIEW") {
		return 2;
	}
	if (upper == "SYNONYM") {
		return 3;
	}
	return 4;
}

} // namespace

std::vector<TableInfo> FetchTables(FusionTransport &transport, const RequestContext &context,
                                   const std::vector<std::string> &types) {
	const auto rows = QueryPaged(transport, context, metadata::TablesByTypes(types));

	// One name can arrive as both a table and a view; keeping both would make
	// the catalog ambiguous, so the more concrete kind wins.
	std::unordered_map<std::string, TableInfo> best;
	std::vector<std::string> order;
	for (const auto &row : rows) {
		TableInfo table;
		table.name = Field(row, "TABLE_NAME");
		if (table.name.empty()) {
			continue;
		}
		table.type = Field(row, "TABLE_TYPE");
		table.remarks = Field(row, "REMARKS");
		table.table_id = Field(row, "TABLE_ID");

		const auto key = Upper(table.name);
		const auto existing = best.find(key);
		if (existing == best.end()) {
			order.push_back(key);
			best.emplace(key, std::move(table));
			continue;
		}
		if (TypePriority(table.type) < TypePriority(existing->second.type)) {
			existing->second = std::move(table);
		}
	}

	std::vector<TableInfo> tables;
	tables.reserve(order.size());
	for (const auto &key : order) {
		tables.push_back(best.at(key));
	}
	std::sort(tables.begin(), tables.end(),
	          [](const TableInfo &a, const TableInfo &b) { return Upper(a.name) < Upper(b.name); });
	return tables;
}

int64_t FetchTableCount(FusionTransport &transport, const RequestContext &context,
                        const std::vector<std::string> &types) {
	try {
		const auto rows = Query(transport, context, metadata::TableCount(types));
		if (rows.empty()) {
			return -1;
		}
		return IntField(rows.front(), "TABLE_COUNT", -1);
	} catch (const FusionError &) {
		// A count is a convenience, not a requirement: an instance that will
		// not answer it must not stop the listing that follows.
		return -1;
	}
}

std::vector<ColumnInfo> FetchColumnsOfTables(FusionTransport &transport, const RequestContext &context,
                                             const std::vector<TableInfo> &tables) {
	// Maps the FND id back to the name, so a batched response can be split up.
	std::unordered_map<std::string, std::string> name_by_id;
	std::vector<std::string> ids;
	for (const auto &table : tables) {
		if (!table.table_id.empty()) {
			name_by_id.emplace(table.table_id, table.name);
			ids.push_back(table.table_id);
		}
	}

	std::vector<ColumnInfo> columns;
	std::unordered_set<std::string> seen;
	for (size_t start = 0; start < ids.size(); start += metadata::COLUMN_BATCH_SIZE) {
		const auto end = std::min(start + metadata::COLUMN_BATCH_SIZE, ids.size());
		const std::vector<std::string> batch(ids.begin() + static_cast<long>(start), ids.begin() + static_cast<long>(end));

		for (const auto &row : QueryPaged(transport, context, metadata::ColumnsByTableIds(batch))) {
			ColumnInfo column;
			column.table_name = Field(row, "TABLE_NAME");
			if (column.table_name.empty()) {
				const auto id = Field(row, "TABLE_ID");
				const auto known = name_by_id.find(id);
				if (known == name_by_id.end()) {
					continue;
				}
				column.table_name = known->second;
			}
			column.name = Field(row, "COLUMN_NAME");
			if (column.name.empty()) {
				continue;
			}
			// The dictionary aliases are shifted: DECIMAL_DIGITS carries the
			// precision and NUM_PREC_RADIX the scale. Un-shifted here, once, so
			// that nothing downstream has to know.
			column.type_name = Field(row, "TYPE_NAME");
			column.precision = IntField(row, "DECIMAL_DIGITS");
			column.scale = IntField(row, "NUM_PREC_RADIX");
			column.ordinal = IntField(row, "ORDINAL_POSITION");
			column.nullable = IntField(row, "NULLABLE", 1) != 0;
			column.remarks = Field(row, "REMARKS");

			// A quoted and an unquoted spelling of one column are one column.
			auto bare = column.name;
			bare.erase(std::remove(bare.begin(), bare.end(), '"'), bare.end());
			if (!seen.insert(Upper(column.table_name) + "|" + Upper(bare)).second) {
				continue;
			}
			columns.push_back(std::move(column));
		}
	}
	return columns;
}

std::vector<ColumnInfo> FetchColumnsOfView(FusionTransport &transport, const RequestContext &context,
                                           const std::string &view_name) {
	std::vector<ColumnInfo> columns;
	std::unordered_set<std::string> seen;
	for (const auto &row : QueryPaged(transport, context, metadata::ColumnsOfViews(view_name))) {
		ColumnInfo column;
		column.table_name = Field(row, "TABLE_NAME");
		column.name = Field(row, "COLUMN_NAME");
		if (column.name.empty()) {
			continue;
		}
		column.type_name = Field(row, "TYPE_NAME");
		column.precision = IntField(row, "DECIMAL_DIGITS");
		column.scale = IntField(row, "NUM_PREC_RADIX");
		column.ordinal = IntField(row, "ORDINAL_POSITION");
		column.nullable = IntField(row, "NULLABLE", 1) != 0;

		auto bare = column.name;
		bare.erase(std::remove(bare.begin(), bare.end(), '"'), bare.end());
		if (!seen.insert(Upper(column.table_name) + "|" + Upper(bare)).second) {
			continue;
		}
		columns.push_back(std::move(column));
	}
	return columns;
}

std::vector<std::string> FetchPrimaryKey(FusionTransport &transport, const RequestContext &context,
                                         const std::string &table_name) {
	auto rows = Query(transport, context, metadata::PrimaryKeys(table_name));
	std::sort(rows.begin(), rows.end(), [](const ReportRow &a, const ReportRow &b) {
		return IntField(a, "KEY_SEQ") < IntField(b, "KEY_SEQ");
	});

	std::vector<std::string> key_columns;
	for (const auto &row : rows) {
		auto name = Field(row, "COLUMN_NAME");
		if (!name.empty()) {
			key_columns.push_back(std::move(name));
		}
	}
	return key_columns;
}

} // namespace ofquack
