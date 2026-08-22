#include "ofquack/metadata_cache.hpp"

#include "duckdb/common/file_system.hpp"
#include "duckdb/main/appender.hpp"

#include <chrono>

namespace duckdb {

namespace {

//! Bumped to 2: caches written before the dictionary listing was fixed hold a
//! silently truncated table list and no expected count, so nothing marks them
//! as partial. Dropping them is cheaper than explaining to every user why a
//! refresh is needed.
constexpr const char *SCHEMA_VERSION = "2";

//! Bumping this is how an incompatible layout change is handled: the old tables
//! are dropped rather than migrated, since everything in them can be refetched.
constexpr const char *CREATE_META = "CREATE TABLE IF NOT EXISTS CACHE_META (KEY VARCHAR PRIMARY KEY, VALUE VARCHAR)";

constexpr const char *CREATE_TABLES = R"(
CREATE TABLE IF NOT EXISTS CACHED_TABLES (
    ENDPOINT_KEY VARCHAR,
    TABLE_NAME VARCHAR,
    TABLE_TYPE VARCHAR,
    REMARKS VARCHAR,
    TABLE_ID VARCHAR,
    FETCHED_AT_EPOCH BIGINT,
    PRIMARY KEY (ENDPOINT_KEY, TABLE_NAME)
))";

constexpr const char *CREATE_COLUMNS = R"(
CREATE TABLE IF NOT EXISTS CACHED_COLUMNS (
    ENDPOINT_KEY VARCHAR,
    TABLE_NAME VARCHAR,
    COLUMN_NAME VARCHAR,
    TYPE_NAME VARCHAR,
    PRECISION BIGINT,
    SCALE BIGINT,
    ORDINAL BIGINT,
    NULLABLE BOOLEAN,
    REMARKS VARCHAR,
    FETCHED_AT_EPOCH BIGINT,
    PRIMARY KEY (ENDPOINT_KEY, TABLE_NAME, COLUMN_NAME)
))";

//! Written as the sole row of a table whose column list came back empty, so
//! that "asked, and the answer was nothing" is distinguishable from "never
//! asked". Not a legal Oracle column name, which is what keeps it unambiguous.
constexpr const char *NO_COLUMNS_MARKER = "!ofquack:no-columns";

std::string DefaultCachePath() {
	auto fs = FileSystem::CreateLocal();
	const auto home = fs->GetHomeDirectory();
	if (home.empty()) {
		return {};
	}
	const auto directory = fs->JoinPath(home, ".ofquack");
	try {
		if (!fs->DirectoryExists(directory)) {
			fs->CreateDirectory(directory);
		}
	} catch (const std::exception &) {
		return {};
	}
	return fs->JoinPath(directory, "metadata.duckdb");
}

//! Seconds since the epoch, as C++ sees them.
//!
//! Freshness is compared against this rather than against SQL now(), because
//! now() carries a time zone and the stored value would not: a cache written in
//! UTC and read back in any other zone looked hours stale, so every lookup
//! missed and the cache never did anything at all.
int64_t NowEpochSeconds() {
	return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

//! Ages a row out. A TTL of zero or less means "never expire".
std::string FreshnessPredicate(int64_t ttl_seconds) {
	if (ttl_seconds <= 0) {
		return {};
	}
	return " AND FETCHED_AT_EPOCH > " + std::to_string(NowEpochSeconds() - ttl_seconds);
}

std::string Escape(const std::string &value) {
	std::string escaped;
	escaped.reserve(value.size());
	for (const char c : value) {
		if (c == '\'') {
			escaped.push_back('\'');
		}
		escaped.push_back(c);
	}
	return escaped;
}

} // namespace

std::string EndpointKey(const std::string &endpoint, const std::string &report_path) {
	return endpoint + "|" + report_path;
}

MetadataCache &MetadataCache::Get() {
	static MetadataCache cache;
	static std::once_flag opened;
	std::call_once(opened, [&]() { cache.Open(DefaultCachePath()); });
	return cache;
}

void MetadataCache::ResetForTesting(const std::string &path) {
	auto &cache = Get();
	std::lock_guard<std::mutex> guard(cache.lock);
	cache.connection.reset();
	cache.database.reset();
	cache.Open(path);
}

void MetadataCache::Open(const std::string &requested_path) {
	path = requested_path;

	// Read-write first; a second DuckDB process holding the file is the usual
	// reason this fails, and it is a downgrade rather than an error.
	if (!path.empty()) {
		try {
			DBConfig config;
			database = make_uniq<DuckDB>(path, &config);
			connection = make_uniq<Connection>(*database);
			mode = CacheMode::READ_WRITE;
			EnsureSchema();
			return;
		} catch (const std::exception &) {
			database.reset();
			connection.reset();
		}

		try {
			DBConfig config;
			config.options.access_mode = AccessMode::READ_ONLY;
			database = make_uniq<DuckDB>(path, &config);
			connection = make_uniq<Connection>(*database);
			mode = CacheMode::READ_ONLY;
			return;
		} catch (const std::exception &) {
			database.reset();
			connection.reset();
		}
	}

	// Last resort: a cache that lives as long as the process. Still better than
	// asking Fusion the same question twice in one session.
	try {
		database = make_uniq<DuckDB>(nullptr);
		connection = make_uniq<Connection>(*database);
		mode = CacheMode::MEMORY;
		path.clear();
		EnsureSchema();
	} catch (const std::exception &) {
		database.reset();
		connection.reset();
	}
}

void MetadataCache::EnsureSchema() {
	if (!connection) {
		return;
	}
	try {
		connection->Query(CREATE_META);
		auto version = connection->Query("SELECT VALUE FROM CACHE_META WHERE KEY = 'schema_version'");
		const bool matches =
		    version && !version->HasError() && version->RowCount() == 1 &&
		    version->GetValue(0, 0).ToString() == SCHEMA_VERSION;
		if (!matches) {
			// Everything here can be refetched, so a layout change drops rather
			// than migrates.
			connection->Query("DROP TABLE IF EXISTS CACHED_TABLES");
			connection->Query("DROP TABLE IF EXISTS CACHED_COLUMNS");
			connection->Query("DELETE FROM CACHE_META WHERE KEY = 'schema_version'");
			connection->Query(std::string("INSERT INTO CACHE_META VALUES ('schema_version', '") + SCHEMA_VERSION +
			                  "')");
		}
		connection->Query(CREATE_TABLES);
		connection->Query(CREATE_COLUMNS);
		connection->Query("CHECKPOINT");
	} catch (const std::exception &) {
		// A cache that cannot hold a schema is a cache that always misses.
		mode = CacheMode::MEMORY;
	}
}

CacheMode MetadataCache::Mode() {
	std::lock_guard<std::mutex> guard(lock);
	return mode;
}

std::string MetadataCache::Path() {
	std::lock_guard<std::mutex> guard(lock);
	return path;
}

idx_t MetadataCache::CountTables(const std::string &endpoint_key) {
	std::lock_guard<std::mutex> guard(lock);
	if (!connection) {
		return 0;
	}
	auto result = connection->Query("SELECT count(*) FROM CACHED_TABLES WHERE ENDPOINT_KEY = '" +
	                                Escape(endpoint_key) + "'");
	if (!result || result->HasError() || result->RowCount() != 1) {
		return 0;
	}
	return result->GetValue(0, 0).GetValue<idx_t>();
}

idx_t MetadataCache::CountColumns(const std::string &endpoint_key) {
	std::lock_guard<std::mutex> guard(lock);
	if (!connection) {
		return 0;
	}
	// The marker rows are bookkeeping, not columns anyone asked about.
	auto result = connection->Query("SELECT count(*) FROM CACHED_COLUMNS WHERE ENDPOINT_KEY = '" +
	                                Escape(endpoint_key) + "' AND COLUMN_NAME <> '" + NO_COLUMNS_MARKER + "'");
	if (!result || result->HasError() || result->RowCount() != 1) {
		return 0;
	}
	return result->GetValue(0, 0).GetValue<idx_t>();
}

int64_t MetadataCache::ExpectedTables(const std::string &endpoint_key) {
	std::lock_guard<std::mutex> guard(lock);
	if (!connection) {
		return -1;
	}
	auto result = connection->Query("SELECT VALUE FROM CACHE_META WHERE KEY = 'tables_expected:" +
	                                Escape(endpoint_key) + "'");
	if (!result || result->HasError() || result->RowCount() != 1) {
		return -1;
	}
	try {
		return std::stoll(result->GetValue(0, 0).ToString());
	} catch (const std::exception &) {
		return -1;
	}
}

void MetadataCache::SetExpectedTables(const std::string &endpoint_key, int64_t expected) {
	std::lock_guard<std::mutex> guard(lock);
	if (!connection || mode == CacheMode::READ_ONLY || expected < 0) {
		return;
	}
	const auto key = "tables_expected:" + Escape(endpoint_key);
	connection->Query("DELETE FROM CACHE_META WHERE KEY = '" + key + "'");
	connection->Query("INSERT INTO CACHE_META VALUES ('" + key + "', '" + std::to_string(expected) + "')");
	connection->Query("CHECKPOINT");
}

// Kept in CACHE_META rather than a table of its own: a key is one short row
// per table, and a new table would mean a schema bump that drops every cache
// out there. Column names are joined with a character Oracle does not allow in
// an identifier.

namespace {
constexpr char PK_SEPARATOR = '\n';
}

bool MetadataCache::TryGetPrimaryKey(const std::string &endpoint_key, const std::string &table_name,
                                     std::vector<std::string> &key_columns) {
	std::lock_guard<std::mutex> guard(lock);
	if (!connection) {
		return false;
	}
	try {
		auto result = connection->Query("SELECT VALUE FROM CACHE_META WHERE KEY = 'pk:" + Escape(endpoint_key) + ":" +
		                                Escape(StringUtil::Upper(table_name)) + "'");
		if (!result || result->HasError() || result->RowCount() != 1) {
			return false;
		}
		key_columns.clear();
		const auto joined = result->GetValue(0, 0).ToString();
		size_t at = 0;
		while (at < joined.size()) {
			const auto next = joined.find(PK_SEPARATOR, at);
			key_columns.push_back(joined.substr(at, next == std::string::npos ? std::string::npos : next - at));
			if (next == std::string::npos) {
				break;
			}
			at = next + 1;
		}
		return true;
	} catch (const std::exception &) {
		return false;
	}
}

void MetadataCache::PutPrimaryKey(const std::string &endpoint_key, const std::string &table_name,
                                  const std::vector<std::string> &key_columns) {
	std::lock_guard<std::mutex> guard(lock);
	if (!connection || mode == CacheMode::READ_ONLY) {
		return;
	}
	try {
		std::string joined;
		for (const auto &column : key_columns) {
			if (!joined.empty()) {
				joined.push_back(PK_SEPARATOR);
			}
			joined += column;
		}
		const auto key = "pk:" + Escape(endpoint_key) + ":" + Escape(StringUtil::Upper(table_name));
		connection->Query("DELETE FROM CACHE_META WHERE KEY = '" + key + "'");
		connection->Query("INSERT INTO CACHE_META VALUES ('" + key + "', '" + Escape(joined) + "')");
		connection->Query("CHECKPOINT");
	} catch (const std::exception &) {
		// Best effort, like every other write here.
	}
}

bool MetadataCache::TryGetTables(const std::string &endpoint_key, int64_t ttl_seconds,
                                 std::vector<ofquack::TableInfo> &tables) {
	const auto expected = ExpectedTables(endpoint_key);

	std::lock_guard<std::mutex> guard(lock);
	if (!connection) {
		return false;
	}
	try {
		auto result = connection->Query("SELECT TABLE_NAME, TABLE_TYPE, REMARKS, TABLE_ID FROM CACHED_TABLES"
		                                " WHERE ENDPOINT_KEY = '" +
		                                Escape(endpoint_key) + "'" + FreshnessPredicate(ttl_seconds) +
		                                " ORDER BY TABLE_NAME");
		if (!result || result->HasError() || result->RowCount() == 0) {
			return false;
		}
		if (expected >= 0 && static_cast<int64_t>(result->RowCount()) < expected) {
			// Fewer than the instance said it has: this list was cut short.
			// Serving it would hide part of the dictionary for a week.
			return false;
		}
		for (idx_t row = 0; row < result->RowCount(); row++) {
			ofquack::TableInfo table;
			table.name = result->GetValue(0, row).ToString();
			table.type = result->GetValue(1, row).ToString();
			table.remarks = result->GetValue(2, row).IsNull() ? "" : result->GetValue(2, row).ToString();
			table.table_id = result->GetValue(3, row).IsNull() ? "" : result->GetValue(3, row).ToString();
			tables.push_back(std::move(table));
		}
		return true;
	} catch (const std::exception &) {
		return false;
	}
}

bool MetadataCache::TryGetColumns(const std::string &endpoint_key, const std::string &table_name, int64_t ttl_seconds,
                                  std::vector<ofquack::ColumnInfo> &columns) {
	std::lock_guard<std::mutex> guard(lock);
	if (!connection) {
		return false;
	}
	try {
		auto result = connection->Query(
		    "SELECT COLUMN_NAME, TYPE_NAME, PRECISION, SCALE, ORDINAL, NULLABLE, REMARKS FROM CACHED_COLUMNS"
		    " WHERE ENDPOINT_KEY = '" +
		    Escape(endpoint_key) + "' AND upper(TABLE_NAME) = upper('" + Escape(table_name) + "')" +
		    FreshnessPredicate(ttl_seconds) + " ORDER BY ORDINAL");
		if (!result || result->HasError() || result->RowCount() == 0) {
			return false;
		}
		for (idx_t row = 0; row < result->RowCount(); row++) {
			ofquack::ColumnInfo column;
			column.table_name = table_name;
			column.name = result->GetValue(0, row).ToString();
			if (column.name == NO_COLUMNS_MARKER) {
				// A recorded empty answer: cached, and cached as empty.
				continue;
			}
			column.type_name = result->GetValue(1, row).IsNull() ? "" : result->GetValue(1, row).ToString();
			column.precision = result->GetValue(2, row).IsNull() ? 0 : result->GetValue(2, row).GetValue<int64_t>();
			column.scale = result->GetValue(3, row).IsNull() ? 0 : result->GetValue(3, row).GetValue<int64_t>();
			column.ordinal = result->GetValue(4, row).IsNull() ? 0 : result->GetValue(4, row).GetValue<int64_t>();
			column.nullable = result->GetValue(5, row).IsNull() || result->GetValue(5, row).GetValue<bool>();
			column.remarks = result->GetValue(6, row).IsNull() ? "" : result->GetValue(6, row).ToString();
			columns.push_back(std::move(column));
		}
		return true;
	} catch (const std::exception &) {
		return false;
	}
}

void MetadataCache::PutTables(const std::string &endpoint_key, const std::vector<ofquack::TableInfo> &tables) {
	std::lock_guard<std::mutex> guard(lock);
	if (!connection || mode == CacheMode::READ_ONLY) {
		return;
	}
	try {
		connection->Query("DELETE FROM CACHED_TABLES WHERE ENDPOINT_KEY = '" + Escape(endpoint_key) + "'");
		Appender appender(*connection, "CACHED_TABLES");
		const auto now = Value::BIGINT(NowEpochSeconds());
		for (const auto &table : tables) {
			appender.BeginRow();
			appender.Append(Value(endpoint_key));
			appender.Append(Value(table.name));
			appender.Append(Value(table.type));
			appender.Append(Value(table.remarks));
			appender.Append(Value(table.table_id));
			appender.Append(now);
			appender.EndRow();
		}
		appender.Close();
		connection->Query("CHECKPOINT");
	} catch (const std::exception &) {
		// Caching is best effort: failing to write must not fail the query the
		// user actually asked for.
	}
}

void MetadataCache::PutColumns(const std::string &endpoint_key, const std::string &table_name,
                               const std::vector<ofquack::ColumnInfo> &columns) {
	std::lock_guard<std::mutex> guard(lock);
	if (!connection || mode == CacheMode::READ_ONLY) {
		return;
	}
	try {
		connection->Query("DELETE FROM CACHED_COLUMNS WHERE ENDPOINT_KEY = '" + Escape(endpoint_key) +
		                  "' AND upper(TABLE_NAME) = upper('" + Escape(table_name) + "')");
		Appender appender(*connection, "CACHED_COLUMNS");
		const auto now = Value::BIGINT(NowEpochSeconds());
		if (columns.empty()) {
			// "This table has no columns we can read" is an answer, and one that
			// cost a request to obtain. Without something written down it is
			// indistinguishable from never having asked, so every connection
			// would ask again -- for exactly the objects Fusion refuses to
			// describe, which are the ones most likely to be looked at twice.
			// The marker is filtered out on the way back.
			appender.BeginRow();
			appender.Append(Value(endpoint_key));
			appender.Append(Value(table_name));
			appender.Append(Value(std::string(NO_COLUMNS_MARKER)));
			appender.Append(Value(std::string()));
			appender.Append(Value::BIGINT(0));
			appender.Append(Value::BIGINT(0));
			appender.Append(Value::BIGINT(-1));
			appender.Append(Value::BOOLEAN(true));
			appender.Append(Value(std::string()));
			appender.Append(now);
			appender.EndRow();
		}
		for (const auto &column : columns) {
			appender.BeginRow();
			appender.Append(Value(endpoint_key));
			appender.Append(Value(table_name));
			appender.Append(Value(column.name));
			appender.Append(Value(column.type_name));
			appender.Append(Value::BIGINT(column.precision));
			appender.Append(Value::BIGINT(column.scale));
			appender.Append(Value::BIGINT(column.ordinal));
			appender.Append(Value::BOOLEAN(column.nullable));
			appender.Append(Value(column.remarks));
			appender.Append(now);
			appender.EndRow();
		}
		appender.Close();
		connection->Query("CHECKPOINT");
	} catch (const std::exception &) {
	}
}

void MetadataCache::InvalidateTables(const std::string &endpoint_key) {
	std::lock_guard<std::mutex> guard(lock);
	if (!connection || mode == CacheMode::READ_ONLY) {
		return;
	}
	connection->Query("DELETE FROM CACHED_TABLES WHERE ENDPOINT_KEY = '" + Escape(endpoint_key) + "'");
	connection->Query("CHECKPOINT");
}

void MetadataCache::InvalidateColumns(const std::string &endpoint_key, const std::string &table_name) {
	std::lock_guard<std::mutex> guard(lock);
	if (!connection || mode == CacheMode::READ_ONLY) {
		return;
	}
	auto sql = "DELETE FROM CACHED_COLUMNS WHERE ENDPOINT_KEY = '" + Escape(endpoint_key) + "'";
	if (!table_name.empty()) {
		sql += " AND upper(TABLE_NAME) = upper('" + Escape(table_name) + "')";
	}
	connection->Query(sql);
	connection->Query("CHECKPOINT");
}

} // namespace duckdb
