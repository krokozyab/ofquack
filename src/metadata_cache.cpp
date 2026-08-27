#include "ofquack/metadata_cache.hpp"

#include "duckdb/common/file_system.hpp"
#include "duckdb/main/appender.hpp"
#include "ofquack/host_throttle.hpp"
#include "ofquack/jwt.hpp"
#include "ofquack/token_cache.hpp"

#include <chrono>
#include <cstdint>

namespace duckdb {

namespace {

//! Bumped to 2: caches written before the dictionary listing was fixed hold a
//! silently truncated table list and no expected count, so nothing marks them
//! as partial. Dropping them is cheaper than explaining to every user why a
//! refresh is needed.
constexpr const char *SCHEMA_VERSION = "3";

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

constexpr const char *CREATE_ORDER_KEYS = R"(
CREATE TABLE IF NOT EXISTS CACHED_ORDER_KEYS (
    ENDPOINT_KEY VARCHAR,
    TABLE_NAME VARCHAR,
    KEY_COLUMNS VARCHAR,
    FETCHED_AT_EPOCH BIGINT,
    PRIMARY KEY (ENDPOINT_KEY, TABLE_NAME)
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
	const auto directory = fs->JoinPath(home, ".fusion_scanner");
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

void CheckedQuery(Connection &connection, const std::string &sql) {
	auto result = connection.Query(sql);
	if (!result || result->HasError()) {
		throw std::runtime_error(result ? result->GetError() : "DuckDB returned no cache query result");
	}
}

void SafeRollback(Connection &connection) {
	try {
		if (connection.HasActiveTransaction()) {
			connection.Rollback();
		}
	} catch (const std::exception &) {
	}
}

} // namespace

std::string EndpointKey(const ofquack::FusionConfig &config) {
	std::string principal;
	if (config.auth == ofquack::AuthMode::BASIC) {
		principal = "basic:" + config.username;
	} else {
		auto token = config.token;
		if (token.empty()) {
			token = ofquack::TokenCache::Get().Lookup(ofquack::HostOf(config.endpoint)).access_token;
		}
		const auto subject = ofquack::ParseJwtClaims(token).subject;
		principal = "bearer:" + (subject.empty() ? std::string("unknown") : subject);
	}
	const auto part = [](const std::string &value) {
		return std::to_string(value.size()) + ":" + value;
	};
	return part(config.endpoint) + part(config.report_path) + part(principal);
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
	cache.table_revisions.clear();
	cache.all_column_revisions.clear();
	cache.column_revisions.clear();
	cache.next_revision = 1;
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
			auto version = connection->Query("SELECT VALUE FROM CACHE_META WHERE KEY = 'schema_version'");
			if (!version || version->HasError() || version->RowCount() != 1 ||
			    version->GetValue(0, 0).ToString() != SCHEMA_VERSION) {
				throw std::runtime_error("the read-only metadata cache has an incompatible schema");
			}
			CheckedQuery(*connection, "SELECT 1 FROM CACHED_TABLES LIMIT 0");
			CheckedQuery(*connection, "SELECT 1 FROM CACHED_COLUMNS LIMIT 0");
			CheckedQuery(*connection, "SELECT 1 FROM CACHED_ORDER_KEYS LIMIT 0");
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
		CheckedQuery(*connection, CREATE_META);
		auto version = connection->Query("SELECT VALUE FROM CACHE_META WHERE KEY = 'schema_version'");
		const bool matches = version && !version->HasError() && version->RowCount() == 1 &&
		                     version->GetValue(0, 0).ToString() == SCHEMA_VERSION;
		if (!matches) {
			// Everything here can be refetched, so a layout change drops rather
			// than migrates.
			connection->BeginTransaction();
			try {
				CheckedQuery(*connection, "DROP TABLE IF EXISTS CACHED_TABLES");
				CheckedQuery(*connection, "DROP TABLE IF EXISTS CACHED_COLUMNS");
				CheckedQuery(*connection, "DROP TABLE IF EXISTS CACHED_ORDER_KEYS");
				CheckedQuery(*connection, "DELETE FROM CACHE_META");
				CheckedQuery(*connection,
				             std::string("INSERT INTO CACHE_META VALUES ('schema_version', '") + SCHEMA_VERSION + "')");
				connection->Commit();
			} catch (const std::exception &) {
				SafeRollback(*connection);
				throw;
			}
		}
		CheckedQuery(*connection, CREATE_TABLES);
		CheckedQuery(*connection, CREATE_COLUMNS);
		CheckedQuery(*connection, CREATE_ORDER_KEYS);
		CheckedQuery(*connection, "CHECKPOINT");
	} catch (const std::exception &) {
		throw;
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
	auto result =
	    connection->Query("SELECT count(*) FROM CACHED_TABLES WHERE ENDPOINT_KEY = '" + Escape(endpoint_key) + "'");
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

idx_t MetadataCache::CountFreshTables(const std::string &endpoint_key, int64_t ttl_seconds) {
	std::lock_guard<std::mutex> guard(lock);
	if (!connection) {
		return 0;
	}
	auto result = connection->Query("SELECT count(*) FROM CACHED_TABLES WHERE ENDPOINT_KEY = '" + Escape(endpoint_key) +
	                                "'" + FreshnessPredicate(ttl_seconds));
	if (!result || result->HasError() || result->RowCount() != 1) {
		return 0;
	}
	return result->GetValue(0, 0).GetValue<idx_t>();
}

idx_t MetadataCache::CountFreshColumns(const std::string &endpoint_key, int64_t ttl_seconds) {
	std::lock_guard<std::mutex> guard(lock);
	if (!connection) {
		return 0;
	}
	auto result =
	    connection->Query("SELECT count(*) FROM CACHED_COLUMNS WHERE ENDPOINT_KEY = '" + Escape(endpoint_key) +
	                      "' AND COLUMN_NAME <> '" + NO_COLUMNS_MARKER + "'" + FreshnessPredicate(ttl_seconds));
	if (!result || result->HasError() || result->RowCount() != 1) {
		return 0;
	}
	return result->GetValue(0, 0).GetValue<idx_t>();
}

idx_t MetadataCache::CountFreshDescribedTables(const std::string &endpoint_key, int64_t ttl_seconds) {
	std::lock_guard<std::mutex> guard(lock);
	if (!connection) {
		return 0;
	}
	auto result = connection->Query("SELECT count(DISTINCT upper(TABLE_NAME)) FROM CACHED_COLUMNS"
	                                " WHERE ENDPOINT_KEY = '" +
	                                Escape(endpoint_key) + "'" + FreshnessPredicate(ttl_seconds));
	if (!result || result->HasError() || result->RowCount() != 1) {
		return 0;
	}
	return result->GetValue(0, 0).GetValue<idx_t>();
}

uint64_t MetadataCache::TablesRevision(const std::string &endpoint_key) {
	std::lock_guard<std::mutex> guard(lock);
	const auto found = table_revisions.find(endpoint_key);
	return found == table_revisions.end() ? 0 : found->second;
}

uint64_t MetadataCache::ColumnsRevision(const std::string &endpoint_key, const std::string &table_name) {
	std::lock_guard<std::mutex> guard(lock);
	uint64_t revision = 0;
	const auto all = all_column_revisions.find(endpoint_key);
	if (all != all_column_revisions.end()) {
		revision = all->second;
	}
	const auto key = endpoint_key + "\n" + StringUtil::Upper(table_name);
	const auto one = column_revisions.find(key);
	if (one != column_revisions.end() && one->second > revision) {
		revision = one->second;
	}
	return revision;
}

int64_t MetadataCache::ExpectedTables(const std::string &endpoint_key) {
	std::lock_guard<std::mutex> guard(lock);
	if (!connection) {
		return -1;
	}
	auto result =
	    connection->Query("SELECT VALUE FROM CACHE_META WHERE KEY = 'tables_expected:" + Escape(endpoint_key) + "'");
	if (!result || result->HasError() || result->RowCount() != 1) {
		return -1;
	}
	try {
		return std::stoll(result->GetValue(0, 0).ToString());
	} catch (const std::exception &) {
		return -1;
	}
}

namespace {
constexpr char PK_SEPARATOR = '\n';
}

bool MetadataCache::TryGetOrderKey(const std::string &endpoint_key, const std::string &table_name, int64_t ttl_seconds,
                                   std::vector<std::string> &key_columns) {
	std::lock_guard<std::mutex> guard(lock);
	if (!connection) {
		return false;
	}
	try {
		auto result = connection->Query("SELECT KEY_COLUMNS FROM CACHED_ORDER_KEYS WHERE ENDPOINT_KEY = '" +
		                                Escape(endpoint_key) + "' AND upper(TABLE_NAME) = upper('" +
		                                Escape(table_name) + "')" + FreshnessPredicate(ttl_seconds));
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

void MetadataCache::PutOrderKey(const std::string &endpoint_key, const std::string &table_name,
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
		connection->BeginTransaction();
		CheckedQuery(*connection, "DELETE FROM CACHED_ORDER_KEYS WHERE ENDPOINT_KEY = '" + Escape(endpoint_key) +
		                              "' AND upper(TABLE_NAME) = upper('" + Escape(table_name) + "')");
		CheckedQuery(*connection, "INSERT INTO CACHED_ORDER_KEYS VALUES ('" + Escape(endpoint_key) + "', '" +
		                              Escape(table_name) + "', '" + Escape(joined) + "', " +
		                              std::to_string(NowEpochSeconds()) + ")");
		connection->Commit();
	} catch (const std::exception &) {
		SafeRollback(*connection);
		// Best effort, like every other write here.
	}
}

bool MetadataCache::TryGetTables(const std::string &endpoint_key, int64_t ttl_seconds,
                                 std::vector<ofquack::TableInfo> &tables) {
	std::lock_guard<std::mutex> guard(lock);
	if (!connection) {
		return false;
	}
	try {
		int64_t expected = -1;
		auto expected_result = connection->Query("SELECT VALUE FROM CACHE_META WHERE KEY = 'tables_expected:" +
		                                         Escape(endpoint_key) + "'");
		if (expected_result && !expected_result->HasError() && expected_result->RowCount() == 1) {
			try {
				expected = std::stoll(expected_result->GetValue(0, 0).ToString());
			} catch (const std::exception &) {
				expected = -1;
			}
		}
		auto result =
		    connection->Query("SELECT TABLE_NAME, TABLE_TYPE, REMARKS, TABLE_ID FROM CACHED_TABLES"
		                      " WHERE ENDPOINT_KEY = '" +
		                      Escape(endpoint_key) + "'" + FreshnessPredicate(ttl_seconds) + " ORDER BY TABLE_NAME");
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

bool MetadataCache::PutTables(const std::string &endpoint_key, const std::vector<ofquack::TableInfo> &tables,
                              int64_t expected) {
	std::lock_guard<std::mutex> guard(lock);
	// Without the independent count, a BI Publisher response truncated at an
	// arbitrary page is indistinguishable from a complete dictionary. Serve the
	// fetched rows to the current caller, but never make them authoritative for a
	// week by persisting them.
	if (!connection || mode == CacheMode::READ_ONLY || expected < 0) {
		return false;
	}
	try {
		connection->BeginTransaction();
		CheckedQuery(*connection, "DELETE FROM CACHED_TABLES WHERE ENDPOINT_KEY = '" + Escape(endpoint_key) + "'");
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
		const auto expected_key = "tables_expected:" + Escape(endpoint_key);
		CheckedQuery(*connection, "DELETE FROM CACHE_META WHERE KEY = '" + expected_key + "'");
		CheckedQuery(*connection,
		             "INSERT INTO CACHE_META VALUES ('" + expected_key + "', '" + std::to_string(expected) + "')");
		connection->Commit();
		table_revisions[endpoint_key] = next_revision++;
		return true;
	} catch (const std::exception &) {
		SafeRollback(*connection);
		// Caching is best effort: failing to write must not fail the query the
		// user actually asked for.
		return false;
	}
}

void MetadataCache::PutColumns(const std::string &endpoint_key, const std::string &table_name,
                               const std::vector<ofquack::ColumnInfo> &columns) {
	PutColumnsBatch(endpoint_key, {{table_name, columns}});
}

bool MetadataCache::PutColumnsBatch(
    const std::string &endpoint_key,
    const std::vector<std::pair<std::string, std::vector<ofquack::ColumnInfo>>> &columns_by_table) {
	std::lock_guard<std::mutex> guard(lock);
	if (!connection || mode == CacheMode::READ_ONLY || columns_by_table.empty()) {
		return columns_by_table.empty();
	}
	try {
		connection->BeginTransaction();
		for (const auto &entry : columns_by_table) {
			CheckedQuery(*connection, "DELETE FROM CACHED_COLUMNS WHERE ENDPOINT_KEY = '" + Escape(endpoint_key) +
			                              "' AND upper(TABLE_NAME) = upper('" + Escape(entry.first) + "')");
		}
		Appender appender(*connection, "CACHED_COLUMNS");
		const auto now = Value::BIGINT(NowEpochSeconds());
		for (const auto &entry : columns_by_table) {
			const auto &table_name = entry.first;
			const auto &columns = entry.second;
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
		}
		appender.Close();
		connection->Commit();
		for (const auto &entry : columns_by_table) {
			column_revisions[endpoint_key + "\n" + StringUtil::Upper(entry.first)] = next_revision++;
		}
		return true;
	} catch (const std::exception &) {
		SafeRollback(*connection);
		return false;
	}
}

std::shared_ptr<std::mutex> MetadataCache::PopulationMutex(const std::string &resource_key) {
	std::lock_guard<std::mutex> guard(population_lock);
	auto &entry = population_mutexes[resource_key];
	if (!entry) {
		entry = std::make_shared<std::mutex>();
	}
	return entry;
}

void MetadataCache::InvalidateTables(const std::string &endpoint_key) {
	std::lock_guard<std::mutex> guard(lock);
	if (!connection || mode == CacheMode::READ_ONLY) {
		return;
	}
	try {
		connection->BeginTransaction();
		CheckedQuery(*connection, "DELETE FROM CACHED_TABLES WHERE ENDPOINT_KEY = '" + Escape(endpoint_key) + "'");
		CheckedQuery(*connection, "DELETE FROM CACHED_COLUMNS WHERE ENDPOINT_KEY = '" + Escape(endpoint_key) + "'");
		CheckedQuery(*connection, "DELETE FROM CACHED_ORDER_KEYS WHERE ENDPOINT_KEY = '" + Escape(endpoint_key) + "'");
		CheckedQuery(*connection, "DELETE FROM CACHE_META WHERE KEY = 'tables_expected:" + Escape(endpoint_key) + "'");
		connection->Commit();
		table_revisions[endpoint_key] = next_revision++;
		all_column_revisions[endpoint_key] = next_revision++;
	} catch (const std::exception &) {
		SafeRollback(*connection);
	}
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
	try {
		connection->BeginTransaction();
		CheckedQuery(*connection, sql);
		auto key_sql = "DELETE FROM CACHED_ORDER_KEYS WHERE ENDPOINT_KEY = '" + Escape(endpoint_key) + "'";
		if (!table_name.empty()) {
			key_sql += " AND upper(TABLE_NAME) = upper('" + Escape(table_name) + "')";
		}
		CheckedQuery(*connection, key_sql);
		connection->Commit();
		if (table_name.empty()) {
			all_column_revisions[endpoint_key] = next_revision++;
		} else {
			column_revisions[endpoint_key + "\n" + StringUtil::Upper(table_name)] = next_revision++;
		}
	} catch (const std::exception &) {
		SafeRollback(*connection);
	}
}

} // namespace duckdb
