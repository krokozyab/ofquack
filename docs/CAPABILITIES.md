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

### Row-level security is not inherited

Every request runs as the signed-in user, and Fusion checks that this user may
run the report. Neither check restricts *which rows* the report returns.

- **Authentication is not data security.** Oracle is explicit that physical SQL
  against base tables does not necessarily honour Fusion's data-security
  profiles; for HCM the supported path is the `*_SECURED_LIST_V` views. See
  [BI Publisher Secured List Views][secured-list-views]. Signing in as a user
  with a narrow Fusion role does not narrow what this extension can read.
- **`RP_ARB.xdo` is a privileged channel, not a reporting one.** It accepts an
  arbitrary `SELECT` and returns what it produces. Whoever can run it can read
  whatever its execution context can reach, and nothing on this side changes
  that.
- **Grant the report through a purpose-made custom role**, held only by the
  people meant to have that reach, rather than adding it to a broad seeded role.
  That grant is the real control, because it is enforced on Fusion's side where
  a client cannot weaken it. Treat access to this report the way you would treat
  a database account, not a report subscription.
- **`secured_views := true` is a convenience, not a boundary.** It is a textual
  rewrite done on this machine before the statement is sent, so anyone who can
  run a query can simply leave it off. It covers eleven HR tables
  (`src/secured_views.cpp`), it is **off by default**, and it applies only to
  statements sent through `oracle_fusion_query()`. A table read through an
  attached catalog — `SELECT … FROM f.main.PER_ALL_PEOPLE_F` — is never
  rewritten, whatever the setting says.

[secured-list-views]: https://docs.oracle.com/en/cloud/saas/human-resources/ochus/business-intelligence-publisher-secured-list-views.html

### Credentials on this machine

- `CREATE PERSISTENT SECRET` writes `~/.duckdb/stored_secrets` **unencrypted**.
  Redaction hides a password from `duckdb_secrets()`, not from the disk. A
  temporary secret (the default) is not written at all.
- SSO tokens are kept in memory only. The browser profile at
  `~/.fusion_scanner/chrome-profile` does persist, and holds the session cookie.
- JWT signatures are not verified. Fusion authenticates a token when it is
  used; the extension only reads the expiry to know when to ask for another.

---

See also: [the function reference](REFERENCE.md) for every function and
setting, and the [README](../README.md) to start from the beginning.
