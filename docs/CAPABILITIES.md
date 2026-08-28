# What this extension can and cannot do

Written so that the limits are known before they are discovered mid-analysis.
Most of them follow from one fact: Oracle Fusion has no SQL endpoint, and
everything here goes through a BI Publisher report.

## Requires a report deployed in Fusion

`DM_ARB.xdm` and `RP_ARB.xdo`, taking a `p_sql` parameter, must exist in your
instance. Without them nothing works — this is not something the extension can
supply. See the README.

## Read-only

BI Publisher runs a query and returns rows. There is no write path, so
`INSERT`, `UPDATE`, `DELETE` and `CREATE TABLE` against an attached catalog are
refused rather than quietly doing something local.

## Everything is a report run

Each query is a SOAP call that opens a BI Publisher session on the server.
Consequences worth planning around:

- **Latency is seconds, not milliseconds**, even for a trivial query.
- **One request at a time per host.** Sessions are expensive and the server
  accumulates them, so requests are serialised deliberately. A join across two
  Fusion tables runs them one after the other.
- **Reading the dictionary is a query too**, which is why metadata is cached on
  disk for a week. `oracle_fusion_tables()` builds the complete name index and
  is enough for queries by name. DuckDB's generic tree can list only tables
  whose columns are already cached, so it grows as tables are queried or through
  an explicit module prefetch such as `fusion_scanner_cache_warm(pattern :=
  'AP\_%')`. See
  [the README](../README.md#first-run-index-the-dictionary-names).

## Result shape

- A query returning **no rows** is an error, not an empty table: the result
  carries no columns, so its schema is genuinely unknown.
- Column types on `oracle_fusion_query` are **inferred from the first page**. A
  later row that contradicts the guess is returned as NULL. `all_varchar :=
  true` turns inference off. An attached catalog does not have this problem: it
  types columns from the dictionary.
- Values with leading zeros stay VARCHAR — `'00123'` is an account code.
- A column Oracle returned as NULL arrives as SQL NULL; a column that is
  present but empty arrives as an empty string. They are different.

## Filter pushdown is conservative

Off by default. When enabled, a predicate that cannot be translated *exactly*
raises an error rather than being approximated, because DuckDB removes a
pushed-down filter from its own plan. Refused on purpose:

| Predicate | Why |
|---|---|
| `text_col > 'M'` | Ordering depends on `NLS_SORT`/`NLS_COMP`, which is not negotiated |
| `col = ''` | Oracle stores `''` as NULL, so this means something different there |
| Bare date literals | `NLS_DATE_FORMAT` can reinterpret them; `TO_DATE` with an explicit format is used instead |
| `IN` past 1000 values | Oracle's own limit |
| Any inferred-type column | The comparison Oracle makes and the one DuckDB makes need not agree |

Equality on text *is* pushed: it does not depend on collation.

## Not supported

- **WebAssembly.** No process spawning, no sockets, no libcurl.
- **Writing**, in any form.
- **Automatic token refresh mid-query.** An expired token surfaces as an error
  asking you to sign in again.
- **Primary and foreign keys as constraints** on attached tables. They can be
  read through the metadata functions but are not exposed to the planner.
- **`ROWNUM` with paging.** A statement using `ROWNUM` is sent unchanged and
  fetched in one request, because `ROWNUM` is assigned before `ORDER BY` and
  does not compose with `OFFSET`.

## Security notes

- `CREATE PERSISTENT SECRET` writes `~/.duckdb/stored_secrets` **unencrypted**.
  Redaction hides a password from `duckdb_secrets()`, not from the disk. A
  temporary secret (the default) is not written at all.
- SSO tokens are kept in memory only. The browser profile at
  `~/.fusion_scanner/chrome-profile` does persist, and holds the session cookie.
- JWT signatures are not verified. Fusion authenticates a token when it is
  used; the extension only reads the expiry to know when to ask for another.
- `secured_views := true` rewrites eleven HR tables to their
  `*_SECURED_LIST_V` views. It is **off by default**, so querying those base
  tables directly can return rows the caller is not entitled to see.

---

See also: [the function reference](REFERENCE.md) for every function and
setting, and the [README](../README.md) to start from the beginning.
