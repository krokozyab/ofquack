# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A DuckDB C++ extension that reaches Oracle Fusion's database through BI Publisher: an
arbitrary SELECT is wrapped in a SOAP `runReport` call, the `RP_ARB.xdo` report runs it via
`dbms_xmlgen`, and the rows come back as XML. Fusion exposes no direct SQL endpoint, so this
detour is the whole point of the extension.

The Fusion side requires a pre-deployed OTBI report (`DM_ARB.xdm` / `RP_ARB.xdo`) that takes a
`p_sql` parameter — see README.md. The extension cannot work against a stock Fusion instance.

Target: **DuckDB v1.5.5**, extension-ci-tools **v1.5-variegata**. These two pins and the
`duckdb_version` in the CI workflow must always move together — a loadable extension refuses to
load into any other DuckDB version.

## Build & test

Both submodules must be checked out, and vcpkg must be reachable:

```sh
git submodule update --init --recursive
export VCPKG_TOOLCHAIN_PATH=$HOME/vcpkg/scripts/buildsystems/vcpkg.cmake
export GEN=ninja          # the default Makefile generator is much slower here

make release              # or: make debug
make test                 # runs test/sql/*.test through build/release/test/unittest
```

Artifacts: `build/release/duckdb` (shell with the extension linked in),
`build/release/extension/fusion_scanner/fusion_scanner.duckdb_extension` (loadable binary).

Single test file: `./build/release/test/unittest test/sql/fusion_scanner.test`.

The C++ suites are registered in the extension's own subdirectory, so the
top-level `ctest` reports zero tests — run them there:

```sh
ctest --test-dir build/release/extension/fusion_scanner
./build/release/extension/fusion_scanner/fusion_scanner_pure_test      # ~1s, no DuckDB, no network
./build/release/extension/fusion_scanner/fusion_scanner_adapter_test   # drives the table function
```

**Type-check without building:** `scripts/syntax_check.sh src/<file>.cpp` runs
`c++ -fsyntax-only` against the pinned DuckDB headers — about a second, versus minutes for a
full rebuild. Use it to iterate on compile errors; it cannot catch link errors.

`scripts/check_windows_view.py` catches POSIX calls that leaked into a Windows branch without
waiting ~40 minutes for the CI matrix.

The SQL tests cover registration, secret redaction and every binder error — everything that can
be checked before a network call. Anything that needs a *response* belongs in
`adapter_test.cpp`, which drives the table function against a scripted transport; that is what
the `FusionTransport` seam is for.

## Architecture

The code is cut into layers, and the cut is load-bearing:

- **Layer 1 — pure** (`soap_envelope`, `xml_report`, `error_decoder`): no DuckDB, no network.
  Tested by `pure_test` in about a second.
- **Layer 2 — transport** (`transport`, `soap_transport`, `http_curl`): knows libcurl, knows
  nothing about DuckDB.
- **Layer 4 — adapter** (`fusion_scanner_extension.cpp`, `fusion_secret`, `fusion_connection`,
  `fusion_query_function`): knows DuckDB, reaches Fusion *only* through `FusionTransport`.

Keep it that way: layer 1 must not include `duckdb.hpp` or `curl.h`, and the adapter must not
call `curl_easy_*` or touch tinyxml2 directly.

The request pipeline:

1. `BuildEnvelope` — SOAP `runReport` envelope, user SQL as CDATA in the `p_sql` parameter,
   `sizeOfDataChunkDownload=-1` (BI Publisher's own chunking is unused; paging rewrites the SQL).
2. `SoapTransport::Execute` — libcurl POST with Basic auth (base64 from vendored `src/base64.cpp`).
3. `ExtractReportXML` — tinyxml2 walk to find `<reportBytes>` by *local* name (prefixes are
   stripped everywhere, since Fusion's prefixes vary), then base64-decode.
4. `ParseRows` — the decoded payload contains `<RESULT>` elements whose *text content* is another
   escaped XML document (`<ROWSET><ROW>…`), so each is parsed again as a separate document.

Table-function wiring: `FusionQueryBind` resolves the secret and fetches the first page — the
schema lives in the data, so there is no way to describe the result without it. That page is
carried into `FusionQueryInitGlobal`, and `FusionQueryScan` emits it in `STANDARD_VECTOR_SIZE`
chunks. `MaxThreads()` returns 1: BI Publisher sessions are expensive and the server accumulates
them, so the scan is deliberately serial.

`tinyxml2` is aliased as `tx2` in `xml_report.cpp` to avoid a symbol collision with MSXML on
Windows — keep it.

### Testing against a fake Fusion

`ScopedTransportFactory` swaps the transport for the lifetime of the scope, so the adapter can be
driven against scripted SOAP responses:

```cpp
ScopedTransportFactory installed([&](const FusionConfig &config) {
    return std::make_shared<FakeTransport>(script, config);
});
DuckDB db(nullptr);
Connection connection(db);
connection.Query("SELECT * FROM oracle_fusion_query(...)");
```

See `test/cpp/adapter_test.cpp`. Anything that would otherwise need credentials belongs there.

## Extension API notes (v1.5.5)

- `ExtensionUtil` was **removed in v1.4.0**; its header is now a `static_assert(false)` trap.
  Registration goes through `ExtensionLoader`: `loader.RegisterFunction(fn)`,
  `loader.RegisterSecretType(type)`, `loader.SetDescription(...)`.
- Entry point is `DUCKDB_CPP_EXTENSION_ENTRY(fusion_scanner, loader)`. The old `fusion_scanner_init` /
  `fusion_scanner_version` / `fusion_scanner_shutdown` trio no longer exists — which is why
  `curl_global_init` sits behind a `std::once_flag` and there is no paired
  `curl_global_cleanup`: there is no shutdown hook to call it from, and calling it from a static
  destructor would race libcurl's background threads.
- The version string comes from `EXT_VERSION_FUSION_SCANNER`, which extension-ci-tools defines from
  `EXTENSION_VERSION` in `extension_config.cmake`.
- **Do not set `CMAKE_CXX_STANDARD`.** It is a cache variable DuckDB owns and sets to 11;
  raising it from here raises it for DuckDB's own targets too, and only for those configured
  after that point, producing a mixed C++11/C++17 build. `static constexpr` members are
  implicitly inline from C++17, so the halves emit a strong and a weak definition of the same
  symbol and the link fails on ELF with `multiple definition of
  duckdb::BufferedFileWriter::DEFAULT_OPEN_FLAGS`. macOS links it anyway — it only shows up on
  Linux CI. Use `target_compile_features(<target> PRIVATE cxx_std_17)`.
- Consequence of that C++17 switch: `base64.h` declares its `string_view` overloads only under
  `__cplusplus >= 201703L`, so passing a bare `const char*` to `base64_decode` is now ambiguous.
  Call it with an explicit `std::string` — that is the overload C++11 used to pick.

## Reference implementations

- `~/projects/ofjdbc` — the author's Kotlin JDBC driver for the same Fusion/BIP detour. Source
  of truth for the dictionary SQL (`metadata/MetadataQueries.kt`), retry/backoff, pagination,
  type inference, and the browser/CDP SSO flow (`auth/BrowserAuthenticator.kt`).
- `~/projects/quack-oracle` — the author's `oracle_scanner` extension. Working example of
  `StorageExtension`/`ATTACH`, secrets, and filter pushdown. **It is built against DuckDB
  `main`, not v1.5.5**: names are `Identifier` there but `string` here, and
  `SetChildCardinality` does not exist in v1.5.5. Copy its structure, not its types verbatim.
- `~/projects/quack-oracle/duckdb` — full DuckDB clone with every tag through v1.5.5.

## Public API

```sql
CREATE SECRET fusion (TYPE oracle_fusion, ENDPOINT …, REPORT_PATH …, USERNAME …, PASSWORD …);
SELECT * FROM oracle_fusion_query('SELECT … FROM …', secret := 'fusion', fetch_size := 500);
```

Secret lookup order: `secret :=` by name → `endpoint :=` by scope → the sole `oracle_fusion`
secret. Several secrets and no name is an error, not a guess.

`oracle_fusion_wsdl_query` still exists as a stub whose bind throws a migration message. It was
kept through `0.2.0` and is now due for removal.

## Resilience

Defaults match the JDBC driver's, so both clients load an instance the same way: 3 attempts,
1s base delay, ×2, capped at 30s, ±20% jitter; connect 30s / read 120s; breaker opens after 5
consecutive failures and probes once after 60s.

Three rules that are easy to break by accident:

- **One request at a time per host** (`HostThrottle`, default 1). Not about our resources —
  every `runReport` opens a BI Publisher session the server holds on to, and a few parallel
  scans leave hundreds behind. The slot is held for the whole request, so this bounds
  concurrency, not rate. Throttle and breaker are keyed by host and shared process-wide.
- **A refusal is not a failure.** `PermanentError` (bad SQL, missing table, rejected password)
  is never retried and does not trip the breaker: it says nothing about the instance's health,
  and tripping on it would block every other query. Only `RetryableError` counts. The same rule
  applies to what the HTTP client throws, not just to statuses — a `CancelledError` from Ctrl-C
  and a `PermanentError` from a bad CA file are both excluded, or a few interrupted queries
  would close the breaker on a host that was answering perfectly well.
- **Half-open means one probe.** `RequireClosed` holds a `probe_in_flight` flag until the probe
  reports back; without it every caller that arrived after the recovery window saw `HALF_OPEN`
  and went through together. It is also checked *after* the throttle slot, not before, or a
  queue of callers that all passed the check while the breaker was closed would run one after
  another into an instance that failed on the first of them.

`ExecuteWithRetry` takes its sleep and its randomness as parameters, which is the only reason
the loop is testable without waiting.

## Paging and types

Paging rewrites the statement — BI Publisher's own chunking (`sizeOfDataChunkDownload`) is not
used, and the report exposes nothing else. `fetch_size` rows per request, default 500, `0` for a
single request.

Two rules here are the answer to bugs that produced wrong results rather than errors, and both
cost a request:

- **Only an empty page ends a scan.** A short page used to, and that is wrong: the report
  truncates a response that grows too large without saying so, and a truncated page is
  indistinguishable from the last one. Every scan therefore ends with one request that comes back
  empty. A result smaller than one page costs two requests, not one.
- **A cut-off block yields its complete rows, marked `truncated`.** The cut lands mid-element, so
  the block fails to parse; `ParseRows` keeps everything up to the last `</ROW>` and sets
  `ParsedReport::truncated`. A paged scan continues from the rows it received, so a cut costs one
  extra request and nothing else. With paging off (`fetch_size := 0`, or a statement with its own
  `OFFSET`/`ROWNUM`) there is nothing to continue from, and the scan fails naming how many rows
  and bytes arrived — that number is the only measurement we have of the report's limit. This was
  the dictionary-listing bug: the cut block was skipped as unparseable, the page looked empty,
  and empty meant the end. The JDBC driver has the same cut and hides it: TagSoup swallows the
  broken tail and its pager treats a short page as the last.
- **A statement with no `ORDER BY` of its own is given one before it is paged.** `OFFSET`/`FETCH`
  partitions a result the server has ordered; each page is a separate execution, and Oracle owes
  no two executions the same row order, so without this a page can repeat rows the previous one
  returned and skip others — invisibly, since every page is well formed. **Which order is as
  important as having one**: anything that makes Oracle sort the whole table costs the whole table
  on every page, and a large table never returns its first row — `ORDER BY` over all hundred
  columns of `XLA_AE_LINES` sat for two minutes for its first 500 rows.
- **An attached table is read by keyset, not by OFFSET.** `OFFSET n` costs O(n) on every page
  even through an index, so a full read of a large table is quadratic — `AP_INVOICES_ALL` sat for
  four minutes without a row. The scan (`PagingMode::KEYSET`) asks for the rows *after the last
  one it saw*: `WHERE (key) > (last) ORDER BY key FETCH FIRST n ROWS ONLY`, with the composite
  comparison expanded by `SeekPredicate` (Oracle has no row-value comparison) and the values
  written back by `KeyLiteral` per type — text from the report, typed by the dictionary, formats
  spelt out so NLS settings cannot reinterpret them. The key (`FusionAttachedState::OrderKey`,
  cached in `CACHE_META` as `key:<endpoint>:<TABLE>`) is the primary key, else a unique index over
  NOT NULL columns (a NULL in the key is a row nothing sorts after), else `ROWID`. Key columns are
  added to the select list when not projected — the seek has to read them back. A key column of a
  type `KeyKindOf` cannot write as a literal drops the scan to OFFSET with `ORDER BY` by name; a
  view, which has no key, is ordered by every projected column, skipping LOBs, and paged by OFFSET.
  `oracle_fusion_query` has no dictionary to ask and wraps the statement
  (`SELECT * FROM (…) ORDER BY 1, 2, …`), which needs the column count and so costs one retake
  of the first page — and is expensive on a large unkeyed result, so a query over a big table
  should carry its own `ORDER BY` on an indexed key. When Oracle refuses that order
  (`ORA-00932` for a CLOB, `ORA-00997` for a LONG — `FND_VIEWS.TEXT`), the scan finds the
  offending columns by halving: `OrderProbe` asks `SELECT * FROM (SELECT * FROM (…) WHERE ROWNUM
  <= 1) ORDER BY <subset>` — one row, no sort, the refusal is compile-time — about 2k·log₂n
  requests for k LOBs among n columns, then orders by the rest. **There is no single-request
  way**: Oracle SQL has no function that reports the type of a CLOB column — `DUMP` and `VSIZE`
  reject it with the same `ORA-00932`, verified live. The retried statement lives in the global
  state, not the bind data, which is read-only by then. `stable_paging := false` (or
  `SET fusion_scanner_stable_paging = false`) turns it off.

A report that ignores the row-limiting clause would now never let a scan end, so a page whose
first row equals the previous page's first row fails the query instead.

The rewrite is skipped, and the first page taken as the whole result, when the statement is not
a SELECT, already carries `OFFSET`/`FETCH`, or uses `ROWNUM` (assigned before `ORDER BY`, so it
does not compose with `OFFSET` — pairing them silently returns the wrong rows). Those keywords
are found by `FindKeyword`, which lexes: `SELECT 'OFFSET' FROM t` is still pageable.

`NormalizeSql` strips comments and collapses whitespace in one pass, **keeping `/*+ hints */`** —
an Oracle hint is lexically a block comment, and dropping it discards the plan the author asked
for. It also leaves string literals byte for byte intact; the naive `\s+` replacement rewrites
`'a   b'`, which is data.

Types are inferred from the first page (first `TYPE_SAMPLE_ROWS` values per column). One value
that does not fit drops the whole column to VARCHAR. Leading zeros keep a column VARCHAR:
`'00123'` is an account code. A later row that contradicts the inferred type becomes NULL rather
than failing the query — `all_varchar := true` turns inference off entirely.

## Metadata and its cache

`oracle_fusion_tables()` and `oracle_fusion_columns(name)` read Fusion's dictionary through the
same report as everything else, so **every metadata question costs a SOAP call measured in
seconds**. That is the constraint the whole design answers: results are cached in a DuckDB
database of its own at `~/.fusion_scanner/metadata.duckdb`, keyed by endpoint + report path so a
development and a production instance never share rows, with a one-week TTL.

The cache is a separate database rather than tables in the user's: it has to work for an
in-memory session, must not appear in the user's catalog, and is shared between connections.
A cache error is always a miss, never an error the user sees — `Open()` falls back read-write →
read-only → memory, and `fusion_scanner_cache_status()` reports which. (The read-only rung is
untested in practice: DuckDB v1.5.5 on macOS did not take an exclusive lock when a second
process held the file, so the downgrade never triggered. It stays as insurance.)

Freshness is compared against an epoch integer computed in C++, **not** against SQL `now()`:
`now()` carries a time zone and the stored value does not, so a cache written in UTC and read
back anywhere else looked stale and every lookup missed.

Dictionary SQL lives in `metadata_queries.cpp`, ported from the JDBC driver. Two things there
must not be "tidied":

- tables come from `FND_VIEWS`/`FND_TABLES`, not `ALL_TABLES`, because only Fusion's own
  dictionary carries `TABLE_ID` — and `TABLE_ID` is how columns are looked up. Views are not in
  `FND_COLUMNS` at all and come from `ALL_TAB_COLUMNS`;
- the column queries alias `data_precision` as `DECIMAL_DIGITS` and `data_scale` as
  `NUM_PREC_RADIX` — shifted by one from what the names say. `metadata_fetch.cpp` un-shifts them
  once; correcting one end without the other turns `NUMBER(10,0)` into `DECIMAL(0,10)`.

**The table listing seeks, it does not skip.** Each page asks for the names sorting after the
last name of the previous one. `OFFSET 20000 ROWS` makes the server sort and discard twenty
thousand rows before returning a page, whereas seeking keeps the cost independent of depth.
An earlier, uninstrumented run using a `ROWNUM` wrapper appeared to stop near 4,000 objects; its
instance, report version and response size were not recorded, so that is not evidence of a fixed
row limit. A live check on 2026-08-28 with the same projection returned ROWNUM pages at offsets
0, 4,000 and 26,000, and the complete seek listing returned 28,978 objects in 16 seconds. Seek
stays because its cost is flat, and the independent count below is the correctness guard.
Columns still page by `OFFSET`, which is safe because they are asked ten tables at a time and
never run deep; their wider rows keep a separate conservative page size of 400.

**`FetchTables` asks the instance for its own `COUNT(DISTINCT UPPER(table_name))` first and
throws if the listing falls short of it.** Inside the fetcher rather than at one call site,
because a partial dictionary that looks complete gets cached for a week and every later lookup
then misses; the catalog and the cache warmer need that guard as much as `oracle_fusion_tables()`
does. The count must stay `DISTINCT`: the listing collapses a name that exists as both a table
and a view, so counting rows of the union would report every complete listing as short. An empty
page is retried once on a fresh session, since an exhausted BI Publisher session also returns
nothing. `fusion_scanner_metadata_page_size` (default 2,000) is the lever when it still stops short.

Unlike the JDBC driver, names are escaped before interpolation (`QuoteLiteral`) and non-numeric
`TABLE_ID`s are dropped rather than concatenated.

## ATTACH

```sql
ATTACH 'my_secret' AS f (TYPE oracle_fusion);
SELECT NAME FROM f.main.GL_JE_HEADERS WHERE ...;
```

`FusionCatalog` derives from `DuckCatalog` and hangs a `DefaultGenerator` on the table
`CatalogSet`. That is what makes laziness cheap:

- **`ATTACH` costs zero requests.** The schema is fixed and the secret is already known.
- `SELECT … FROM f.main.T` resolves through `CreateDefaultEntry(name)` — one table's columns,
  no schema listing.
- `GetDefaultEntries()` (the expensive one) answers only from cache and never goes to the
  network, so `SHOW TABLES` on a cold catalog lists nothing rather than blocking for minutes.
  `oracle_fusion_tables()` indexes the names; the generic tree lists only tables whose columns
  were fetched by a named lookup or an explicit patterned `fusion_scanner_cache_warm()`.
- Column types come from the dictionary here, not from inference.

Things that will bite if changed:

- `Create()` returns `nullptr` for an unknown name. That is not an error — DuckDB asks every
  attached catalog about names belonging to none of them, and a catalog that throws breaks
  those lookups.
- **`LookupSchema` clears `created_all_entries` on the generator before every lookup.** After
  any full scan of the table set (`SHOW TABLES`, a client expanding the tree, the "did you mean"
  search after a miss) `CatalogSet` sets that flag and never offers an unknown name to the
  generator again. With a deliberately partial listing that froze the catalog: `PO_LINES_ALL`
  "did not exist" on a live instance right after `XLA_AE_LINES` had worked. The cost is that a
  scan re-runs `GetDefaultEntries()` each time, which is a cache read.
- `GetStorage()` must throw `NotImplementedException`. The base implementation throws
  `InternalException`, which marks the database invalid and kills the connection.
- `GetVirtualColumns()`/`GetRowIdColumns()` return empty. A report has no rowid, and the
  default offers one, after which the scan is handed a column id it cannot map.
- `CreateSchema` must delegate for `main`: `DuckCatalog::Initialize` creates it through there.
- `SupportsCreateTable` is a separate hook — `CREATE TABLE` does not go through
  `PlanCreateTableAs`, so without it a local table would quietly appear inside the catalog and
  shadow a real Fusion one.
- The attachment is **not** marked `READ_ONLY`: DuckDB refuses an in-memory database in
  read-only mode, and `info.path` is replaced with `:memory:` because a `DuckCatalog` opens a
  local storage manager from it. Read-only is enforced by the catalog's own refusals instead.

Projection pushdown is always on: every selected column travels back as base64-encoded XML.
Filter pushdown is behind `fusion_scanner_filter_pushdown`, **off by default** — DuckDB removes a
filter it has handed to a scan, so anything not translatable exactly must fail rather than be
approximated. Refused on purpose: ordered comparison on text (depends on `NLS_SORT`), the empty
string (Oracle stores `''` as NULL), bare date literals (`NLS_DATE_FORMAT`), `IN` past 1000,
and any column whose type was inferred rather than read from the dictionary.

## SSO

```sql
CREATE SECRET fusion (TYPE oracle_fusion, PROVIDER browser, ENDPOINT …, REPORT_PATH …,
                      SSO_LOGIN_URL 'https://<host>');
SELECT * FROM fusion_scanner_sso_login();     -- opens a browser, waits for a person
```

No client secret, no registered application, no password in this process. The browser performs
whatever the organisation requires, and Fusion hands its own signed-in session a token through
`/fscmRestApi/tokenrelay` (guarded by `/fscmRestApi/anticsrf`, which is what stops another site
doing the same). The flow is ported from the JDBC driver.

Load-bearing decisions:

- **A `SELECT` never opens a browser.** Sign-in is its own function; a query with no token
  fails and names it. `RequireUsableCredentials` enforces that at bind time, before anything is
  sent — and is deliberately *not* inside `ResolveFusionConfig`, because the SSO functions
  resolve the same configuration precisely in order to report on the missing token.
- **`CREATE SECRET` is not interactive either** — it is routinely run from scripts.
- Tokens live in memory only (`TokenCache`, keyed by host, process-wide, never per connection:
  otherwise every connection would open its own window). Persistence comes from the browser
  profile at `~/.fusion_scanner/chrome-profile`, which holds the cookie that gets a new token without
  a new login.
- The JWT signature is **not** verified, on purpose: Fusion authenticates the token when it is
  used, and all this needs from it is `exp`. The expiry margin is capped at half the token's
  life, or a short-lived token would be discarded on arrival.
- `fusion_scanner_sso_status()` never prints the token: it is a live credential and would land in
  scrollback and query history.
- If the browser exits without opening a debugging port, it handed the URL to an instance
  already running under that profile; the retry uses a throwaway profile.

The WebSocket client is ours (`websocket.cpp`) rather than libcurl's, whose WS API is
experimental in every released 8.x and needs a specific build. It only ever speaks to
`ws://127.0.0.1:<port>` — no TLS, no proxy, no permessage-deflate — so it is deliberately
minimal. Do not reuse it for anything else.

**Verified live** up to and including `Runtime.evaluate`: Chrome launches, the port opens,
`/json/list` answers, the handshake completes, the collection script runs and reports `waiting`,
the timeout fires with a usable message, and the process is cleaned up. **Not** verified:
collecting a real token, which needs a real Fusion instance.

## Still outstanding

- primary keys and foreign keys are fetched by `metadata_fetch` but not surfaced as constraints
  on an attached table;
- the token is never refreshed automatically mid-query: a `TokenExpiredError` surfaces as an
  error telling the user to sign in again, rather than re-running the browser flow.
