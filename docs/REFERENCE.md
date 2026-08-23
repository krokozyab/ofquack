# Reference: every function, setting and option

The complete list of what this extension adds to DuckDB, what each item does,
and when you would reach for it.

## How to read this page

Almost everything here is a **table function**: you call it by selecting from
it.

```sql
SELECT * FROM ofquack_sso_login();
```

Oracle spells the same idea `SELECT * FROM TABLE(my_pipelined_function())`.
DuckDB does not need the `TABLE()` wrapper — the function goes straight into
the `FROM` clause.

**A table function does not always just return data.** This is the part that
catches people out, so plainly: some of these functions *do something*.
`SELECT * FROM ofquack_sso_login()` opens a browser window and waits for you to
sign in. `SELECT * FROM ofquack_cache_invalidate()` deletes cached metadata.
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
open a browser; that is [`ofquack_sso_login()`](#ofquack_sso_login)'s job,
because `CREATE SECRET` is routinely run from scripts and must not block
waiting for a person.

#### Parameters

| Parameter | Provider | Meaning |
|---|---|---|
| `ENDPOINT` | both | Your instance, e.g. `https://fa-xxxx-dev1.fa.ocs.oraclecloud.com`. The BI Publisher service path is appended for you; give the full `…/xmlpserver/services/ExternalReportWSSService?WSDL` URL only if yours is non-standard. |
| `REPORT_PATH` | both | Absolute path of the deployed report, e.g. `/Custom/Financials/RP_ARB.xdo`. |
| `SCHEMA` | both | Schema name reported for dictionary objects. Defaults to `FUSION`. |
| `FETCH_SIZE` | both | Rows per request, 1–10000, or `0` for a single request. Default 500. |
| `SECURED_VIEWS` | both | `true` rewrites HR tables to their `*_SECURED_LIST_V` equivalents. |
| `CONNECT_TIMEOUT` | both | Seconds to wait for the connection. Default 30. |
| `READ_TIMEOUT` | both | Seconds to wait for the response. Default 120. Raise it for slow reports. |
| `USERNAME`, `PASSWORD` | config | Fusion credentials, sent as HTTP Basic. |
| `AUTH` | config | `basic` (default) or `bearer`. |
| `TOKEN` | config | A JWT you obtained yourself, for `AUTH bearer`. |
| `SSO_LOGIN_URL` | browser | Where to send the browser. Defaults to the endpoint's host, which is normally right. |
| `CHROME_PATH` | browser | Path to a Chrome/Edge/Chromium binary, when it is not where we look. |
| `CHROME_PROFILE_DIR` | browser | Where the browser profile lives. Default `~/.ofquack/chrome-profile`; it is what remembers you between sessions. |
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

### `ofquack_sso_login()`

**This is the function that actually signs you in.** Calling it launches a
browser window pointed at your Fusion instance, waits while you complete
whatever your organisation requires — password, MFA, Okta, Entra — and then
collects the token Fusion hands its own signed-in session. Nothing in the name
says "and now a window will open", so: it does.

```sql
SELECT * FROM ofquack_sso_login();
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
  `~/.ofquack/chrome-profile` keeps the cookie that gets a fresh token without
  a fresh login.
- If Chrome is already running under that profile it may hand the URL to the
  running instance and exit; the retry uses a throwaway profile automatically.

### `ofquack_sso_status()`

Whether you are signed in, and for how much longer. Touches no network and
opens nothing.

```sql
SELECT * FROM ofquack_sso_status();
```

**Returns** `host`, `have_token`, `subject`, `expires_at`, `should_refresh`,
`expires_in_seconds`.

It never prints the token itself: a live credential in your scrollback and
query history is one more thing to worry about, for no benefit.

### `ofquack_sso_logout()`

Discards the token held for this host. The browser profile is untouched, so the
next `ofquack_sso_login()` will probably not ask for a password.

```sql
SELECT * FROM ofquack_sso_logout();
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
to migrate, and will be deleted a release after 0.1.0.

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

**Writes are refused.** `INSERT`, `CREATE TABLE`, `DROP` and the rest fail with
an explanation, rather than quietly making a local table inside the catalog
that would shadow the real one.

#### `SHOW TABLES` on a cold catalog lists nothing

On purpose. Listing tens of thousands of tables with their columns would be hours of
SOAP calls, so the catalog lists only what it already knows. Warm it first:

```sql
SELECT count(*) FROM oracle_fusion_tables();          -- the names
SELECT * FROM ofquack_cache_warm(pattern := 'AP\_%'); -- and their columns
```

Tables you name directly always work, listed or not.

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
in seconds, so answers are cached on disk at `~/.ofquack/metadata.duckdb`,
keyed by endpoint and report path, for a week.

### `oracle_fusion_tables()`

Lists tables and views, from `FND_TABLES` and `FND_VIEWS`.

```sql
SELECT * FROM oracle_fusion_tables() WHERE table_name LIKE 'AP\_INVOICE%';
```

**Returns** `table_name`, `table_type`, `remarks`, `table_id`.

**Named parameters:** connection parameters, plus `refresh := true` to ignore
the cache, `cache_ttl_seconds`, and `page_size`.

The first call is expensive — tens of thousands of rows, dozens of requests,
minutes. Every call after it is instant, including from a new process. The
extension asks the instance how many objects it holds and refuses a listing
that comes back short, so a partial dictionary never reaches the cache.

### `oracle_fusion_columns(table_name)`

```sql
SELECT * FROM oracle_fusion_columns('AP_INVOICES_ALL');
```

**Returns** `column_name`, `oracle_type`, `duckdb_type`, `precision`, `scale`,
`ordinal`, `nullable`, `remarks`.

**Named parameters:** connection parameters, `refresh`, `cache_ttl_seconds`.

Tables are read from `FND_COLUMNS` by their `TABLE_ID`; views are not in
`FND_COLUMNS` at all and come from `ALL_TAB_COLUMNS`.

### `ofquack_cache_warm()`

Fetches columns for many tables in advance, so that autocomplete and
`SHOW TABLES` have something to work with and later queries do not stop to ask.

```sql
SELECT * FROM ofquack_cache_warm(pattern := 'GL\_%', max_tables := 500);
```

**Returns** `tables_warmed`, `columns_cached`, `tables_without_columns`,
`already_cached`.

**Named parameters:** `pattern` (SQL `LIKE`), `max_tables` (default 200),
`cache_ttl_seconds`.

Bounded by default on purpose: warming every table in the dictionary is hours of calls.
Columns are fetched ten tables per request.

### `ofquack_cache_status()`

```sql
SELECT * FROM ofquack_cache_status();
```

**Returns** `mode`, `path`, `endpoint`, `cached_tables`, `dictionary_tables`,
`complete`, `cached_columns`.

`mode` is `read_write`, `read_only` or `memory`. A second DuckDB process
holding the cache file pushes you down that ladder; it is a slowdown, never an
error. `complete` compares what is cached against what the instance says it
has.

### `ofquack_cache_invalidate()`

Throws cached metadata away, for when Fusion has been patched and the
dictionary has moved under you.

```sql
SELECT * FROM ofquack_cache_invalidate();                            -- everything
SELECT * FROM ofquack_cache_invalidate(table := 'AP_INVOICES_ALL');  -- one table
```

**Returns** `tables_removed`, `columns_removed`.

---

## Housekeeping

### `ofquack_version()`

A scalar function, so no `FROM`:

```sql
SELECT ofquack_version();
-- 0.1.0 (built Aug 22 2026 21:21:36)
```

The build stamp is there for a reason: a loaded extension stays in the process,
so after replacing the binary you may still be running the old one. If the
timestamp is not the one you just built, restart your client.

### `ofquack_attached_scan`

Internal. It is the scan behind an attached table and appears in `EXPLAIN`
output; you never call it yourself.

---

## Settings

Set with `SET`, read with `current_setting()`. They apply to the session.

| Setting | Default | What it does |
|---|---|---|
| `ofquack_stable_paging` | `true` | Gives a paged statement an order, so its pages partition the result instead of sampling it. Turning it off is faster and lets pages repeat and skip rows. |
| `ofquack_filter_pushdown` | `false` | Sends `WHERE` predicates on attached tables to Fusion. Off because DuckDB removes a pushed filter from its own plan, so anything not translatable exactly must fail rather than be approximated. |
| `ofquack_metadata_page_size` | `400` | Rows per page when listing the dictionary. Lower it if a listing keeps stopping short. |

```sql
SET ofquack_filter_pushdown = true;
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
`*_SECURED_LIST_V` views that apply the data security your user is subject to —
`PER_ALL_PEOPLE_F` becomes `PER_PERSON_SECURED_LIST_V`, and so on. Off by
default, because the unsecured tables are what most reporting uses.

---

## Further reading

- [SSO](SSO.md) — how the browser flow works, and what it does not do
- [Metadata and caching](METADATA.md) — where the dictionary comes from, why paging looks the way it does
- [Capabilities and limits](CAPABILITIES.md) — what this can and cannot do
- [Updating](UPDATING.md) — moving to a new DuckDB version
