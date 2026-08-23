#pragma once

#include "duckdb.hpp"
#include "ofquack/metadata_fetch.hpp"

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>

namespace duckdb {

//! How the cache ended up in its current state, reported by
//! ofquack_cache_status() so a silent downgrade is at least visible.
enum class CacheMode {
	READ_WRITE, //!< the normal case
	READ_ONLY,  //!< another process holds the file; reads work, writes do not
	MEMORY,     //!< the file could not be opened at all
};

//! Metadata that survives a restart.
//!
//! Every metadata question costs a BI Publisher call measured in seconds, so
//! asking twice is the thing worth avoiding. The cache is a DuckDB database of
//! its own under ~/.ofquack rather than tables in the user's database: it must
//! work for an in-memory session, must not appear in the user's catalog, and
//! must be shared between connections.
//!
//! DuckDB takes an exclusive lock on a database file, so a second process
//! cannot open it read-write. That is a downgrade, not a failure: the cache
//! falls back to read-only, and then to memory. A cache error is always a miss,
//! never an error the user sees -- being slower is acceptable, refusing to work
//! is not.
class MetadataCache {
public:
	//! The process-wide instance, opened on first use.
	static MetadataCache &Get();

	CacheMode Mode();
	std::string Path();

	//! Rows currently held for this endpoint, for reporting.
	idx_t CountTables(const std::string &endpoint_key);
	idx_t CountColumns(const std::string &endpoint_key);

	//! How many tables the instance said it has when the list was cached, or
	//! -1 if that was never established.
	int64_t ExpectedTables(const std::string &endpoint_key);
	void SetExpectedTables(const std::string &endpoint_key, int64_t expected);

	//! The key a paged read of the table seeks by -- the primary key, or failing
	//! that a unique index over NOT NULL columns -- in key order. An empty list
	//! is a recorded "no key", which is as much an answer as any other. False
	//! on a miss.
	bool TryGetOrderKey(const std::string &endpoint_key, const std::string &table_name,
	                      std::vector<std::string> &key_columns);
	void PutOrderKey(const std::string &endpoint_key, const std::string &table_name,
	                   const std::vector<std::string> &key_columns);

	//! Returns false when nothing is cached for this endpoint, when what is
	//! cached is older than `ttl_seconds` (0 disables expiry), or when it holds
	//! fewer tables than the instance said it has.
	//!
	//! That last case is the important one: a listing cut short by a truncated
	//! response leaves a cache that looks perfectly good and is quietly missing
	//! whole stretches of the dictionary. Treating it as a miss makes the next
	//! call repair it instead of serving the gap for a week.
	bool TryGetTables(const std::string &endpoint_key, int64_t ttl_seconds, std::vector<ofquack::TableInfo> &tables);
	bool TryGetColumns(const std::string &endpoint_key, const std::string &table_name, int64_t ttl_seconds,
	                   std::vector<ofquack::ColumnInfo> &columns);

	void PutTables(const std::string &endpoint_key, const std::vector<ofquack::TableInfo> &tables);
	void PutColumns(const std::string &endpoint_key, const std::string &table_name,
	                const std::vector<ofquack::ColumnInfo> &columns);

	//! Drops cached rows. An empty table name clears the columns of every table.
	void InvalidateTables(const std::string &endpoint_key);
	void InvalidateColumns(const std::string &endpoint_key, const std::string &table_name);

	//! Test seam: reopens against a given path, or in memory when empty.
	static void ResetForTesting(const std::string &path);

private:
	MetadataCache() = default;
	void Open(const std::string &requested_path);
	void EnsureSchema();

	std::mutex lock;
	CacheMode mode = CacheMode::MEMORY;
	std::string path;
	unique_ptr<DuckDB> database;
	unique_ptr<Connection> connection;
};

//! Identifies one Fusion report, so a development and a production instance do
//! not share cached metadata.
std::string EndpointKey(const std::string &endpoint, const std::string &report_path);

} // namespace duckdb
