#pragma once

#include "duckdb.hpp"
#include "ofquack/metadata_fetch.hpp"

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>

namespace duckdb {

//! How the cache ended up in its current state, reported by
//! fusion_scanner_cache_status() so a silent downgrade is at least visible.
enum class CacheMode {
	READ_WRITE, //!< the normal case
	READ_ONLY,  //!< another process holds the file; reads work, writes do not
	MEMORY,     //!< the file could not be opened at all
};

//! Metadata that survives a restart.
//!
//! Every metadata question costs a BI Publisher call measured in seconds, so
//! asking twice is the thing worth avoiding. The cache is a DuckDB database of
//! its own under ~/.fusion_scanner rather than tables in the user's database: it must
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
	idx_t CountFreshTables(const std::string &endpoint_key, int64_t ttl_seconds);
	idx_t CountFreshColumns(const std::string &endpoint_key, int64_t ttl_seconds);
	idx_t CountFreshDescribedTables(const std::string &endpoint_key, int64_t ttl_seconds);
	uint64_t TablesRevision(const std::string &endpoint_key);
	uint64_t ColumnsRevision(const std::string &endpoint_key, const std::string &table_name);

	//! How many tables the instance said it has when the list was cached, or
	//! -1 if that was never established.
	int64_t ExpectedTables(const std::string &endpoint_key);

	//! The key a paged read of the table seeks by -- the primary key, or failing
	//! that a unique index over NOT NULL columns -- in key order. An empty list
	//! is a recorded "no key", which is as much an answer as any other. False
	//! on a miss.
	bool TryGetOrderKey(const std::string &endpoint_key, const std::string &table_name, int64_t ttl_seconds,
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

	//! Replaces the table list and its expected count in one transaction. A list
	//! whose independent count is unknown is not persisted: its completeness
	//! cannot be established, so it must not become authoritative for a week.
	bool PutTables(const std::string &endpoint_key, const std::vector<ofquack::TableInfo> &tables, int64_t expected);
	void PutColumns(const std::string &endpoint_key, const std::string &table_name,
	                const std::vector<ofquack::ColumnInfo> &columns);
	bool PutColumnsBatch(const std::string &endpoint_key,
	                     const std::vector<std::pair<std::string, std::vector<ofquack::ColumnInfo>>> &columns_by_table);

	//! Serialises an expensive cache fill for one logical resource. Callers check
	//! the cache again after acquiring it, so concurrent cold requests do not line
	//! up behind the host throttle only to repeat the same SOAP calls.
	std::shared_ptr<std::mutex> PopulationMutex(const std::string &resource_key);

	//! Drops the complete endpoint snapshot, or one table's columns and ordering
	//! key. An empty table name clears columns and keys for every table.
	void InvalidateTables(const std::string &endpoint_key);
	void InvalidateColumns(const std::string &endpoint_key, const std::string &table_name);

	//! Test seam: reopens against a given path, or in memory when empty.
	static void ResetForTesting(const std::string &path);

private:
	MetadataCache() = default;
	void Open(const std::string &requested_path);
	void EnsureSchema();

	std::mutex lock;
	std::mutex population_lock;
	std::unordered_map<std::string, std::weak_ptr<std::mutex>> population_mutexes;
	uint64_t next_revision = 1;
	std::unordered_map<std::string, uint64_t> table_revisions;
	std::unordered_map<std::string, uint64_t> all_column_revisions;
	std::unordered_map<std::string, uint64_t> column_revisions;
	CacheMode mode = CacheMode::MEMORY;
	std::string path;
	unique_ptr<DuckDB> database;
	unique_ptr<Connection> connection;
};

//! Identifies one Fusion report and authenticated principal, so environments
//! and users with different dictionary visibility do not share metadata.
std::string EndpointKey(const ofquack::FusionConfig &config, const std::string &schema);

//! The principal component of EndpointKey, or empty when a browser secret has
//! no token whose subject can identify the cache owner.
std::string CachePrincipal(const ofquack::FusionConfig &config);

} // namespace duckdb
