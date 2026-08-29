# Reference: every function, setting and option

The complete list of what this extension adds to DuckDB, what each item does,
and when you would reach for it.

## How to read this page

Almost everything here is a **table function**: you call it by selecting from
it.

```sql
SELECT * FROM fusion_scanner_sso_login();
```

Oracle spells the same idea `SELECT * FROM TABLE(my_pipelined_function())`.
DuckDB does not need the `TABLE()` wrapper — the function goes straight into
the `FROM` clause.

**A table function does not always just return data.** This is the part that
catches people out, so plainly: some of these functions *do something*.
`SELECT * FROM fusion_scanner_sso_login()` opens a browser window and waits for you to
sign in. `SELECT * FROM fusion_scanner_cache_invalidate()` deletes cached metadata.
The row that comes back afterwards is the report of what happened, not the
reason for the call. It is the same idea as a PL/SQL function with a side
effect invoked through `SELECT … FROM DUAL`.

Arguments come in two shapes, and both appear below:

- **positional** — `oracle_fusion_columns('GL_JE_HEADERS')`
- **named**, written with `:=` — `oracle_fusion_query('…', fetch_size := 2000)`

---

## Connecting

### `CREATE SECRET … (TYPE oracle_fusion, …)`

Stores where your Fusion instance is and how to authenticate to it, so that
none of it has to be repeated — or typed into a query — again.

A secret is DuckDB's credential store. Without one you would pass the endpoint
and the password as function arguments, where they would end up in the SQL
text, in `duckdb_queries()` and in your shell history.

There are two **providers**, which is DuckDB's word for "kind of secret".

#### `PROVIDER config` — username and password (the default)

```sql
CREATE SECRET fusion (
    TYPE oracle_fusion,
    ENDPOINT 'https://fa-xxxx-dev1.fa.ocs.oraclecloud.com',
    REPORT_PATH '/Custom/Financials/RP_ARB.xdo',
    USERNAME 'sergey.rudenko',
    PASSWORD '…'
);
```

#### `PROVIDER browser` — corporate single sign-on

```sql
CREATE SECRET fusion (
    TYPE oracle_fusion,
    PROVIDER browser,
    ENDPOINT 'https://fa-xxxx-dev1.fa.ocs.oraclecloud.com',
    REPORT_PATH '/Custom/Financials/RP_ARB.xdo'
);
```

Holds no credential at all — only where to sign in. Creating it does **not**
open a browser; that is [`fusion_scanner_sso_login()`](#fusion_scanner_sso_login)'s job,
because `CREATE SECRET` is routinely run from scripts and must not block
waiting for a person.

#### Parameters

| Parameter | Provider | Meaning |
|---|---|---|
| `ENDPOINT` | both | Your instance, e.g. `https://fa-xxxx-dev1.fa.ocs.oraclecloud.com`. The BI Publisher service path is appended for you; give the full `…/xmlpserver/services/ExternalReportWSSService?WSDL` URL only if yours is non-standard. |
| `REPORT_PATH` | both | Absolute path of the deployed report, e.g. `/Custom/Financials/RP_ARB.xdo`. |
| `ON_CAST_ERROR` | both | `null` (default) or `error`: what a value that does not fit its column does. See `on_cast_error` below. |
| `NUMBER_MODE` | both | `double` (default), `decimal` or `text`: what an unconstrained `NUMBER` becomes. See `number_mode` below. |
| `SCHEMA` | both | Owner the dictionary queries filter on, and the schema reported for dictionary objects. Defaults to `FUSION`, which is what every instance seen so far uses. Upper-cased before it is compared. Part of the metadata cache key, so two secrets differing only here keep separate caches. |
| `FETCH_SIZE` | both | Rows per request, 1–10000, or `0` for a single request. Default 500. |
| `SECURED_VIEWS` | both | `true` rewrites HR tables to their `*_SECURED_LIST_V` equivalents. |
| `CONNECT_TIMEOUT` | both | Seconds to wait for the connection. Default 30. |
| `READ_TIMEOUT` | both | Seconds to wait for the response. Default 120. Raise it for slow reports. |
| `USERNAME`, `PASSWORD` | config | Fusion credentials, sent as HTTP Basic. |
| `AUTH` | config | `basic` (default) or `bearer`. |
| `TOKEN` | config | A JWT you obtained yourself, for `AUTH bearer`. |
| `SSO_LOGIN_URL` | browser | Where to send the browser. Defaults to the endpoint's host, which is normally right. |
| `CHROME_PATH` | browser | Path to a Chrome/Edge/Chromium binary, when it is not where we look. |
| `CHROME_PROFILE_DIR` | browser | Where the browser profile lives. Default `~/.fusion_scanner/chrome-profile`; it is what remembers you between sessions. |
| `USE_TEMP_PROFILE` | browser | `true` forces a throwaway profile, so every sign-in starts clean. |
| `SSO_TIMEOUT_SECONDS` | browser | How long to wait for the person at the keyboard. Default 300. |

`duckdb_secrets()` lists your secrets with `PASSWORD` and `TOKEN` redacted.

> **Redaction hides the password from the view, not from the disk.**
> `CREATE PERSISTENT SECRET` writes `~/.duckdb/stored_secrets` in the clear. A
> plain `CREATE SECRET` (the default) lives only for the session.

#### Which secret gets used

Every function below resolves its connection the same way:

1. `secret := 'name'` — by name;
2. `endpoint := 'https://…'` — the secret whose scope matches;
3. neither — the one `oracle_fusion` secret, if exactly one exists.

Several secrets and no name is an error listing them, not a guess.

---

## Signing in with SSO

### `fusion_scanner_sso_login()`

**This is the function that actually signs you in.** Calling it launches a
browser window pointed at your Fusion instance, waits while you complete
whatever your organisation requires — password, MFA, Okta, Entra — and then
collects the token Fusion hands its own signed-in session. Nothing in the name
says "and now a window will open", so: it does.

```sql
SELECT * FROM fusion_scanner_sso_login();
```

**Returns** one row: `host`, `subject` (who you signed in as), `expires_at`,
`signed_in`.

**Named parameters:** the connection parameters, plus `force := true` to sign
in again even though a valid token is already held.

Worth knowing:

- **A `SELECT` never opens a browser.** Query without signing in and the query
  fails, naming this function. That is deliberate — a window appearing in the
  middle of somebody's report would be worse than an error.
- The token lives **in memory only**, shared by every connection in the
  process, and is gone when DuckDB exits.
- You will usually not have to sign in again tomorrow: the browser profile at
  `~/.fusion_scanner/chrome-profile` keeps the cookie that gets a fresh token without
  a fresh login.
- If Chrome is already running under that profile it may hand the URL to the
  running instance and exit; the retry uses a throwaway profile automatically.

### `fusion_scanner_sso_status()`

Whether you are signed in, and for how much longer. Touches no network and
opens nothing.

```sql
SELECT * FROM fusion_scanner_sso_status();
```

**Returns** `host`, `have_token`, `subject`, `expires_at`, `should_refresh`,
`expires_in_seconds`.

It never prints the token itself: a live credential in your scrollback and
query history is one more thing to worry about, for no benefit.

### `fusion_scanner_sso_logout()`

Discards the token held for this host. The browser profile is untouched, so the
next `fusion_scanner_sso_login()` will probably not ask for a password.

```sql
SELECT * FROM fusion_scanner_sso_logout();
```

**Returns** `host`, `token_discarded`.

---

## Running SQL against Fusion

### `oracle_fusion_query(sql)`

Runs one Oracle SQL statement inside the BI Publisher report and returns its
rows as an ordinary DuckDB table.

```sql
SELECT * FROM oracle_fusion_query(
    'SELECT je_header_id, name, currency_code
       FROM GL_JE_HEADERS
      WHERE creation_date > DATE ''2025-01-01'''
);
```

The string is **Oracle SQL**, executed by Oracle. Everything outside it is
DuckDB SQL — see [Two SQL dialects](../README.md#two-sql-dialects-in-one-statement).

**Returns** whatever the statement returns, with column order following your
select list and types inferred from the first page.

**Named parameters:**

| Parameter | Meaning |
|---|---|
| `secret` | Which secret to use, when you have more than one. |
| `endpoint`, `report_path` | Override the secret's. |
| `username`, `password` | Override the secret's. Puts the password into the SQL text — prefer a secret. |
| `fetch_size` | Rows per request, 1–10000. `0` means one request for everything. |
| `all_varchar` | `true` returns every column as text, skipping type inference. |
| `on_cast_error` | What a value that does not fit its column does: `null` (default) reads it as NULL, `error` fails the query and names the value. Applies to attached tables too. |
| `number_mode` | What an Oracle `NUMBER` with no declared precision becomes: `double` (default), `decimal` for `DECIMAL(38,6)`, or `text`. Only reaches types that come from the dictionary — attached tables and `oracle_fusion_columns` — because `oracle_fusion_query` infers from the data instead. |
| `columns` | `oracle_fusion_query` only. A declared schema, `{'ID': 'BIGINT', 'NAME': 'VARCHAR'}`, in the shape `read_csv` uses. Overrides inference **always**, and is the only way to read a result that came back empty, which carries no column names to infer from. A name the report did not return is refused rather than served as a column of NULLs. |
| `secured_views` | `true` rewrites HR tables to their secured views. |
| `stable_paging` | `false` stops the extension adding an `ORDER BY` for paging. Faster, and pages may then repeat and skip rows. |

#### Scenarios

**A quick look at something small.** Nothing to configure:

```sql
SELECT * FROM oracle_fusion_query('SELECT * FROM FND_CURRENCIES_TL WHERE ROWNUM < 20');
```

**Pulling a large table.** Give it your own `ORDER BY` on an indexed key and a
bigger page. Without an `ORDER BY` the extension has to add one over every
column, which makes Oracle sort the whole result before it can return the first
page:

```sql
CREATE TABLE local_lines AS
SELECT * FROM oracle_fusion_query(
    'SELECT * FROM XLA_AE_LINES ORDER BY ae_header_id, ae_line_num',
    fetch_size := 5000
);
```

**Joining Fusion data with a local file.** This is what DuckDB is for — the
join happens on your machine:

```sql
SELECT f.invoice_num, f.invoice_amount, x.comment
FROM oracle_fusion_query('SELECT invoice_id, invoice_num, invoice_amount FROM AP_INVOICES_ALL') f
JOIN read_csv('~/notes.csv') x USING (invoice_id);
```

**Anything that is not a `SELECT`.** There is none. BI Publisher runs the
statement read-only; this extension has no write path to Fusion, by
construction.

#### A query that returns no rows is an error

The result carries no columns, so its schema is unknown and there is nothing to
describe the table with. Add a predicate that matches something, or wrap the
query so that it always returns a row.

### `oracle_fusion_wsdl_query(…)` — removed

The old positional form. It exists only to fail with a message explaining how
to migrate. It was kept through 0.2.0 and is due for deletion in the next
release.

---

## Attaching Fusion as a schema

### `ATTACH 'secret' AS name (TYPE oracle_fusion, …)`

Makes Fusion's tables appear as ordinary tables you can name directly, instead
of passing SQL strings.

```sql
ATTACH 'fusion' AS f (TYPE oracle_fusion);

SELECT invoice_num, invoice_amount
FROM f.AP_INVOICES_ALL
WHERE vendor_id = 12345;
```

The quoted `'fusion'` is the name of your secret, not a file path.

**Options** — the same names as `oracle_fusion_query`'s named parameters:

```sql
ATTACH 'fusion' AS f (TYPE oracle_fusion, FETCH_SIZE 5000);
ATTACH '' AS prod (TYPE oracle_fusion, SECRET prod_secret, REPORT_PATH '/Custom/CloudSQL/RP_ARB.xdo');
```

**What it costs:** `ATTACH` itself makes **no** requests. Naming a table costs
one dictionary read for its columns, cached afterwards. Reading it costs one
request per page.

**Types come from Fusion's dictionary** here rather than from guessing at the
data, so a `NUMBER(10,2)` is a `DECIMAL` whether or not the first page happens
to contain a decimal point.

A `NUMBER` that declares neither precision nor scale — which is how Fusion
declares its amount columns, `GL_JE_LINES.ENTERED_DR` among them — becomes a
`DOUBLE`. There is no scale to give `DECIMAL` and the only one available is
zero, which would round every amount; Oracle writes 0.84 as `.84`, and
`DECIMAL(38,0)` read that as `1`. The cost of `DOUBLE` is that it cannot hold
all 38 digits Oracle allows, so an unconstrained `NUMBER` used as a wide
integer identifier loses its low digits past 2^53. A column with a declared
precision or scale is unaffected and stays exact.

Oracle's `DATE` is a date *and* a time to the second, so it becomes a
`TIMESTAMP`. DuckDB's `DATE` would silently drop the time.

A value that does not fit the type its column was given reads as NULL, because
one odd row should not cost the rest. `on_cast_error := 'error'` fails the query
and names the value instead.

**Writes are refused.** `INSERT`, `CREATE TABLE`, `DROP` and the rest fail with
an explanation, rather than quietly making a local table inside the catalog
that would shadow the real one.

#### Index names; prefetch tree schemas only when useful

**On a machine that has never connected to this instance, an attached schema
looks empty.** `SHOW TABLES` never goes to the network, because DuckDB would
materialise the columns of every name it enumerated. Build the complete name
index once; that is sufficient for every query by name:

```sql
-- Complete browsing surface and the index used by named lookups.
SELECT count(*) FROM oracle_fusion_tables();

-- Optional: make one module visible in a generic tree.
SELECT * FROM fusion_scanner_cache_warm(pattern := 'AP\_%', max_tables := 500);
```

Both kinds of metadata are cached on disk and do not expire, so a new session — or a
new process using the same Fusion principal — can reuse whatever was fetched.

What works cold, and what does not:

| | Cold | Names indexed | Schemas prefetched |
|---|---|---|---|
| `ATTACH` | instant | instant | instant |
| `SHOW TABLES`, tree, autocomplete | empty | still lists only described tables | lists the selected modules |
| `SELECT … FROM f.T` by name | builds the index, then fetches one schema | fetches one schema | uses cached schema |

A table you name directly always works, listed or not. Full generic-tree
enumeration is unsupported; use `oracle_fusion_tables()` to browse all names.

#### When to use `ATTACH` and when to use `oracle_fusion_query`

| | `ATTACH` | `oracle_fusion_query` |
|---|---|---|
| You write | Table names | Oracle SQL as a string |
| Types | From the dictionary | Inferred from the first page |
| Joins, functions, hints | DuckDB does them, after fetching | Oracle does them, before sending |
| Reading a big table end to end | Pages by key — flat cost per page | Pages by `OFFSET` — give it an `ORDER BY` |
| Anything Oracle-specific | No | Yes — it is Oracle SQL |

An Oracle-side join, an analytic function or a hint has to go through
`oracle_fusion_query`. Joining two attached tables works, but DuckDB fetches
both and joins locally, which is usually the wrong way round for large tables.

---

## The dictionary

Every question about Fusion's dictionary is answered by a report call measured
in seconds, so answers are cached on disk at `~/.fusion_scanner/metadata.duckdb`,
keyed by endpoint, report path, and authenticated principal. Nothing expires on
its own; `refresh := true` or deleting the file is what refetches.

### `oracle_fusion_tables()`

Lists tables and views, from `FND_TABLES` and `FND_VIEWS`.

```sql
SELECT * FROM oracle_fusion_tables() WHERE table_name LIKE 'AP\_INVOICE%';
```

**Returns** `table_name`, `table_type`, `remarks`, `table_id`.

**Named parameters:** connection parameters, plus `refresh := true` to ignore
the cache, `cache_ttl_seconds`, and `page_size`.

The first call fetches tens of thousands of names in 2,000-row pages. A measured
28,978-object instance completed in 16 seconds; instance and report limits can
vary. Every call after it is instant, including from a new process. The extension
asks the instance how many objects it holds and refuses a listing that comes
back short, so a partial dictionary never reaches the cache.

### `oracle_fusion_columns(table_name)`

```sql
SELECT * FROM oracle_fusion_columns('AP_INVOICES_ALL');
```

**Returns** `column_name`, `oracle_type`, `duckdb_type`, `precision`, `scale`,
`ordinal`, `nullable`, `remarks`, `lossy`.

`lossy` is `true` when Oracle declared neither precision nor scale, so the
DuckDB type is this extension's choice rather than something the dictionary
stated — and, under every `number_mode` but `text`, a choice that cannot hold
every value the column is allowed to. It is the closest thing to a warning
available: DuckDB v1.5.5 has no channel an extension can put a notice on.

```sql
SELECT column_name, oracle_type, duckdb_type
FROM oracle_fusion_columns('GL_JE_LINES')
WHERE lossy;
```

**Named parameters:** connection parameters, `refresh`, `cache_ttl_seconds`.

Tables are read from `FND_COLUMNS` by their `TABLE_ID`; views are not in
`FND_COLUMNS` at all and come from `ALL_TAB_COLUMNS`.

### `fusion_scanner_cache_warm()`

Optionally fetches columns for a named table family so autocomplete and
`SHOW TABLES` can list that subset. It is not required for queries by name.

```sql
SELECT * FROM fusion_scanner_cache_warm(pattern := 'GL\_%', max_tables := 500);
```

**Returns** `tables_warmed`, `columns_cached`, `tables_without_columns`,
`already_cached`, and the nullable `first_error` for an object-specific failure.

**Named parameters:** required `pattern` (SQL `LIKE`, with `\` as the escape character),
`max_tables` (default 200, zero for no limit), `cache_ttl_seconds`, and
`page_size` — which sizes the *table listing* this warm may have to fetch first,
not the column pages. Column metadata keeps its own 400-row pages and does not
follow this parameter. A missing or empty pattern and a negative limit are
rejected. A deliberate full prefetch must say `pattern := '%'` and
`max_tables := 0`.

Bounded by default on purpose: warming every table in the dictionary is hours of calls.
Columns are fetched and committed ten tables per batch. An empty column result
is cached as a completed lookup, so later warm-ups do not ask for it again. A
read-only cache refuses an explicit warm instead of reporting writes it could
not make.

### `fusion_scanner_cache_status()`

```sql
SELECT * FROM fusion_scanner_cache_status();
```

**Returns** `mode`, `path`, `endpoint`, `cached_tables`, `dictionary_tables`,
`complete`, `cached_columns`, `fresh_tables`, `fresh_columns`, and
`described_tables`, followed by `principal`. The original seven columns retain
their order.

`mode` is `read_write`, `read_only` or `memory`. A second DuckDB process
holding the cache file pushes you down that ladder; it is a slowdown, never an
error. `complete` compares fresh table rows against what the instance says it
has and is `NULL` when that expected count is unknown. `described_tables` is the
number of tables for which a fresh column lookup — including an empty answer —
has been cached. `principal` identifies the account whose cache key is being
reported. Before browser SSO supplies a token subject it is `NULL`, as are all
cache counters: the function cannot know which user's rows to count, and does
not report a misleading zero under the unused `bearer:unknown` key.

### `fusion_scanner_cache_invalidate()`

Throws cached metadata away, for when Fusion has been patched and the
dictionary has moved under you.

```sql
SELECT * FROM fusion_scanner_cache_invalidate();                            -- everything
SELECT * FROM fusion_scanner_cache_invalidate(table_name := 'AP_INVOICES_ALL');  -- one table
```

**Returns** `tables_removed`, `columns_removed`.

Invalidation also removes ordering keys used by stable paging. If the affected
table has already been materialised in an attached DuckDB catalog, detach and
attach that catalog again before querying it; the extension refuses to scan
with the stale schema. A read-only cache refuses invalidation explicitly rather
than reporting a successful no-op.

---

## Housekeeping

### `fusion_scanner_version()`

A scalar function, so no `FROM`:

```sql
SELECT fusion_scanner_version();
-- 0.2.0 (built Aug 28 2026 15:00:34)
```

The build stamp is there for a reason: a loaded extension stays in the process,
so after replacing the binary you may still be running the old one. If the
timestamp is not the one you just built, restart your client.

### `fusion_scanner_attached_scan`

Internal. It is the scan behind an attached table and appears in `EXPLAIN`
output; you never call it yourself.

---

## Settings

Set with `SET`, read with `current_setting()`. They apply to the session.

| Setting | Default | What it does |
|---|---|---|
| `fusion_scanner_stable_paging` | `true` | Gives a paged statement an order, so its pages partition the result instead of sampling it. Turning it off is faster and lets pages repeat and skip rows. |
| `fusion_scanner_filter_pushdown` | `false` | Sends `WHERE` predicates on attached tables to Fusion. Off because DuckDB removes a pushed filter from its own plan, so anything not translatable exactly must fail rather than be approximated. |
| `fusion_scanner_metadata_page_size` | `2000` | Rows per page when building the table-name index. Column metadata keeps its separate 400-row page size. |

```sql
SET fusion_scanner_filter_pushdown = true;
SELECT invoice_num FROM f.AP_INVOICES_ALL WHERE vendor_id = 12345;
```

With pushdown on, `vendor_id = 12345` reaches Oracle and only matching rows
travel back. A predicate that cannot be translated exactly — an ordered
comparison on text, which depends on `NLS_SORT`; a comparison with `''`, which
Oracle stores as `NULL`; a bare date literal, which depends on
`NLS_DATE_FORMAT`; an `IN` list past 1000 — raises an error naming itself, so
that you can turn the setting off rather than receive wrong rows.

---

## Secured HR views

With `secured_views := true`, eleven HR tables are rewritten to the
`*_SECURED_LIST_V` views, which are the ones that apply the data security your
user is subject to — `PER_ALL_PEOPLE_F` becomes `PER_PERSON_SECURED_LIST_V`, and
so on. Off by default, because the unsecured tables are what most reporting uses.

The substitution happens on this machine, before the statement is sent, and only
for `oracle_fusion_query()`: a table read through an attached catalog is never
rewritten. So it makes the secured views convenient to reach; it does not stop
anyone reaching the base tables. What limits that is who holds the role granting
the report — see
[the security notes](CAPABILITIES.md#row-level-security-is-not-inherited).

---

## Further reading

- [SSO](SSO.md) — how the browser flow works, and what it does not do
- [Metadata and caching](METADATA.md) — where the dictionary comes from, why paging looks the way it does
- [Capabilities and limits](CAPABILITIES.md) — what this can and cannot do
- [Updating](UPDATING.md) — moving to a new DuckDB version
