# Ofquack Extension for DuckDB

This repository is based on https://github.com/duckdb/extension-template, check it out if you want to build and ship your own DuckDB extension.

---

Oracle Fusion exposes no SQL endpoint. **Ofquack** reaches its database the way
Oracle leaves open: your `SELECT` is wrapped in a SOAP `runReport` call to BI
Publisher, a report runs it through `dbms_xmlgen`, and the rows come back as
XML — which this extension turns into an ordinary DuckDB result.

Read-only, by construction: BI Publisher cannot write.

---
## Features

**Query Fusion directly.** `SELECT * FROM oracle_fusion_query('SELECT … FROM GL_JE_HEADERS')`, with column order following your select list.

**Or attach it as a database.** `ATTACH 'fusion' AS f (TYPE oracle_fusion)`, then query tables by name, typed from Fusion's own dictionary.

**Corporate SSO.** Sign in through a real browser — Okta, Entra, MFA, whatever your organisation uses — with no client secret and no password in the process.

**Credentials in secrets.** The connection lives in a DuckDB secret, so passwords stay out of SQL text and query history.

**Native column types.** Numbers, dates and timestamps arrive as INTEGER, DECIMAL, DATE and TIMESTAMP rather than as strings; `all_varchar := true` opts out.

**Paging.** Large results are fetched a page at a time, so a wide table need not fit in one SOAP response.

**Cached metadata.** Reading Fusion's dictionary is slow, so the answers are kept on disk between sessions.

**Resilient.** Transient failures are retried with exponential backoff; a failing instance trips a circuit breaker instead of being hammered, and requests to one host are serialised so BI Publisher sessions do not pile up.

A column Oracle returned as NULL arrives as SQL NULL rather than as an empty string.

Further reading: [SSO](docs/SSO.md) · [metadata and caching](docs/METADATA.md) · [capabilities and limits](docs/CAPABILITIES.md)

---

## Installation
### Prerequities
**Create report in OTBI**
   In you fusion instance un-archive _DM_ARB.xdm.catalog_ and _RP_ARB.xdo.catalog_ from [here](https://github.com/krokozyab/ofjdbc/tree/master/otbireport)
into _/Shared Foldrs/Custom/Financials_ folder (that can be different if you will). 

   Installation is simple through the DuckDB Community Extension repository, just type
```
INSTALL ofquack FROM community
LOAD ofquack
```

---

## Usage

Store the connection once, as a DuckDB secret, then query:

```sql
CREATE SECRET fusion (
    TYPE oracle_fusion,
    ENDPOINT 'https://<your-fusion-host>',
    REPORT_PATH '/Custom/Financials/RP_ARB.xdo',
    USERNAME '<username>',
    PASSWORD '<password>'
);

SELECT *
FROM oracle_fusion_query(
    'SELECT currency_code, name, description FROM FND_CURRENCIES_TL WHERE rownum < 10'
);
```

Keeping the credentials in a secret is the point: passed as function arguments
they end up in the SQL text, in `duckdb_queries()` and in your shell history.
`duckdb_secrets()` shows the secret with its password redacted.

> **`CREATE PERSISTENT SECRET` writes `~/.duckdb/stored_secrets` unencrypted.**
> Redaction hides the password from the catalog view, not from the disk. Use a
> temporary secret (the default) if that matters, and rely on the file
> permissions of your home directory otherwise.

## Function signature

```
oracle_fusion_query(sql VARCHAR, <named parameters…>)
    RETURNS TABLE(<dynamic_columns> VARCHAR…)
```

The single positional argument is the SQL to run inside the report. Named
parameters override whatever the secret carries:

| Parameter | Meaning |
|---|---|
| `secret` | Name of the secret to use. Needed only when several are defined. |
| `endpoint` | The Fusion instance, e.g. `https://host.fa.ocs.oraclecloud.com`. The BI Publisher path is appended for you; give a full URL only if yours is non-standard. |
| `report_path` | Absolute path of the report, e.g. `/Custom/Financials/RP_ARB.xdo`. |
| `username`, `password` | Fusion credentials. |
| `fetch_size` | Rows per request, 1–10000. `0` disables paging. |
| `all_varchar` | Return every column as VARCHAR instead of inferring types. |
| `secured_views` | Rewrite HR tables to their `*_SECURED_LIST_V` views. |

### Paging

Large results are fetched a page at a time by appending
`OFFSET … ROWS FETCH NEXT … ROWS ONLY` to your statement — BI Publisher offers
no other paging mechanism. The rewrite is skipped, and one request made, when
the statement already carries `OFFSET`/`FETCH`, uses `ROWNUM`, or is not a
SELECT. A keyword inside a string literal does not count, so
`SELECT 'OFFSET' FROM t` is still paged.

Oracle hints survive: `/*+ FIRST_ROWS(1000) */` reaches the server even though
it is lexically a comment.

### Column types

Types are inferred from the first page — INTEGER, BIGINT, DECIMAL, DATE,
TIMESTAMP or VARCHAR. A column keeps VARCHAR if any sampled value does not fit,
and values with leading zeros keep it VARCHAR too: `'00123'` is an account
code, not the number 123.

Because the guess comes from a sample, a later row can contradict it; such a
value is returned as NULL rather than failing the whole query. Pass
`all_varchar := true` to switch inference off and get the raw text.

If exactly one `oracle_fusion` secret exists it is used automatically. If
several exist, pass `secret := '<name>'` — the extension will not pick one for
you, since guessing would send your credentials to whichever instance happened
to sort first.

### Migrating from `oracle_fusion_wsdl_query`

The old positional form is gone:

```sql
-- before
SELECT * FROM oracle_fusion_wsdl_query(endpoint, user, password, report_path, sql);
-- after
CREATE SECRET fusion (TYPE oracle_fusion, ENDPOINT …, REPORT_PATH …, USERNAME …, PASSWORD …);
SELECT * FROM oracle_fusion_query(sql);
```

Calling the old name reports this migration rather than "function does not
exist". That stub will be removed in a later release.

## Choosing an authentication mode

The secret decides, and the extension cannot work it out for you — it has no
way of knowing whether an instance is behind single sign-on until it tries, and
trying a password against an SSO instance is pointless.

| What the secret contains | Mode used |
|---|---|
| `AUTH 'basic'`, `'bearer'` or `'browser'` | exactly that |
| `PROVIDER browser` | bearer, via sign-in |
| a `TOKEN` | bearer |
| none of the above | basic |

So a secret with `USERNAME` and `PASSWORD` and nothing else uses Basic
authentication; `PROVIDER browser` is what selects single sign-on. A secret
with neither is refused up front, naming both possibilities, rather than
sending an empty credential and reporting Fusion's 401 as a wrong password.

## Signing in with SSO

If your Fusion instance is behind corporate single sign-on, you do not need a
password in a secret at all:

```sql
CREATE SECRET fusion (
    TYPE oracle_fusion,
    PROVIDER browser,
    ENDPOINT 'https://<your-fusion-host>',
    REPORT_PATH '/Custom/Financials/RP_ARB.xdo'
);

SELECT * FROM ofquack_sso_login();
```

The browser is sent to the endpoint's own host, since that is where the
application lives and reaching it unauthenticated is what triggers the sign-on
redirect. `SSO_LOGIN_URL` overrides that, for the instances where sign-in
starts somewhere else.

A browser window opens on your Fusion instance. Sign in the way you normally
do — Okta, Entra, a second factor, whatever your organisation uses — and the
extension collects the token Fusion issues to your signed-in session. There is
no client secret, no registered application, and your password never reaches
this process.

```sql
SELECT * FROM ofquack_sso_status();   -- signed in? until when?
SELECT * FROM ofquack_sso_logout();   -- discard the token
```

The token is kept in memory only and is never written to disk. What does
persist is the browser profile under `~/.ofquack/chrome-profile`, so the next
sign-in is usually a click rather than a password.

Notes:

- **A query never opens a browser by itself.** If you are not signed in, the
  query fails and tells you to run `ofquack_sso_login()`. Sign-in is
  interactive, and an ordinary `SELECT` should not be.
- `CREATE SECRET` does not open a browser either, so it is safe in a script.
- Chrome, Chromium or Edge is required. Set `OFQUACK_CHROME_PATH` or
  `CHROME_PATH` on the secret if it is somewhere unusual.
- On a machine with no browser — a server, CI — obtain a token another way and
  use `AUTH 'bearer', TOKEN '…'` instead.

## Attaching Fusion as a database

```sql
ATTACH 'fusion' AS f (TYPE oracle_fusion);       -- 'fusion' is the secret name
SELECT NAME FROM f.main.GL_JE_HEADERS WHERE LEDGER_ID = 1;
```

Tables appear with the types Fusion's dictionary declares, rather than types
guessed from the data. The attachment is read-only — BI Publisher cannot write
— and `INSERT`, `UPDATE`, `DELETE` and `CREATE TABLE` are refused with an
explanation.

`ATTACH` itself makes no request. The first query about a table fetches that
table's columns; nothing reads the whole dictionary unless you ask it to. As a
consequence `SHOW TABLES` lists only what has been cached so far — run
`SELECT * FROM oracle_fusion_tables()` once to populate it.

Only the columns you select are requested, which matters here: every column
travels back as base64-encoded XML.

### Pushing filters down

```sql
SET ofquack_filter_pushdown = true;
```

Off by default. When on, `WHERE` predicates are translated into the statement
sent to Fusion. A predicate that cannot be translated *exactly* raises an error
rather than being approximated, because DuckDB removes a pushed-down filter
from its own plan — an approximation would silently return wrong rows.

Refused on purpose: ordered comparison of text (Oracle's collation depends on
`NLS_SORT`), comparison with `''` (Oracle stores it as NULL), and `IN` lists
past Oracle's limit of 1000.

## Browsing the dictionary

```sql
SELECT * FROM oracle_fusion_tables();               -- tables and views
SELECT * FROM oracle_fusion_columns('GL_JE_HEADERS');
```

`oracle_fusion_columns` reports each column's Oracle type alongside the DuckDB
type it maps to, its precision, scale and nullability.

Reading Fusion's dictionary is slow — it goes through the same report as
everything else — so results are cached on disk at `~/.ofquack/metadata.duckdb`
for a week, keyed by endpoint and report path. A development and a production
instance never share cached rows.

```sql
SELECT * FROM ofquack_cache_status();               -- where the cache is, what it holds
SELECT * FROM oracle_fusion_tables(refresh := true);        -- bypass it once
SELECT * FROM ofquack_cache_invalidate();                   -- drop it for this endpoint
SELECT * FROM ofquack_cache_invalidate(table := 'GL_JE_HEADERS');
SELECT * FROM ofquack_cache_warm(pattern := 'GL_%');   -- fill the catalog browser
```

If the cache file cannot be opened it degrades to read-only and then to
memory — you may wait longer, but nothing fails. `ofquack_cache_status()` says
which mode is in effect.

### Secured HR views

Passing `secured_views := true` rewrites eleven HR tables to their
`*_SECURED_LIST_V` counterparts, so Fusion's row-level security applies.
Querying the base tables directly can return rows the caller is not entitled to
see. The rewrite is whole-word and ignores string literals.

### Errors

A SOAP fault, a permissions problem or a bad table name now raise an error
carrying the `ORA-` code, instead of quietly returning zero rows — previously
a typo in a table name was indistinguishable from a query that matched nothing.

A query that returns no rows is also an error: the result carries no columns,
so its schema is unknown. Add a predicate that matches at least one row, or
wrap the query so that it always returns one.

## Building

Dependencies (libcurl, OpenSSL, tinyxml2) come from vcpkg:

```shell
git clone https://github.com/Microsoft/vcpkg.git ~/vcpkg
~/vcpkg/bootstrap-vcpkg.sh
export VCPKG_TOOLCHAIN_PATH=$HOME/vcpkg/scripts/buildsystems/vcpkg.cmake
```

Then:

```sh
git submodule update --init --recursive
export GEN=ninja          # the default generator is considerably slower here
make release              # or: make debug
```

Built binaries:

- `./build/release/duckdb` — the DuckDB shell with the extension linked in
- `./build/release/extension/ofquack/ofquack.duckdb_extension` — the loadable binary
- `./build/release/test/unittest` — DuckDB's test runner

The extension is built against DuckDB **v1.5.5**. A loadable extension refuses
to load into any other version, so the `duckdb` submodule, the
`extension-ci-tools` submodule and `duckdb_version` in the CI workflow have to
move together.

## Running the extension

```sh
./build/release/duckdb
```

## Running the tests

Three suites, in increasing order of cost:

```sh
# Pure unit tests: no DuckDB, no network, about a second.
cmake -S test/standalone -B build/pure -G Ninja && cmake --build build/pure
./build/pure/ofquack_pure_test

# Adapter tests: drive the table functions and the catalog against a scripted
# transport -- still no network and no credentials.
./build/release/extension/ofquack/ofquack_adapter_test

# SQL tests.
make test
```

Anything that would otherwise need a live Fusion instance belongs in
`test/cpp/adapter_test.cpp`, which swaps the transport for a scripted one.

### Installing the deployed binaries
To install your extension binaries from S3, you will need to do two things. Firstly, DuckDB should be launched with the
`allow_unsigned_extensions` option set to true. How to set this will depend on the client you're using. Some examples:

CLI:
```shell
duckdb -unsigned
```

Python:
```python
con = duckdb.connect(':memory:', config={'allow_unsigned_extensions' : 'true'})
```

NodeJS:
```js
db = new duckdb.Database(':memory:', {"allow_unsigned_extensions": "true"});
```

Secondly, you will need to set the repository endpoint in DuckDB to the HTTP url of your bucket + version of the extension
you want to install. To do this run the following SQL query in DuckDB:
```sql
SET custom_extension_repository='bucket.s3.eu-west-1.amazonaws.com/<your_extension_name>/latest';
```
Note that the `/latest` path will allow you to install the latest extension version available for your current version of
DuckDB. To specify a specific version, you can pass the version instead.

After running these steps, you can install and load your extension using the regular INSTALL/LOAD commands in DuckDB:
```sql
INSTALL ofquack
LOAD ofquack
```
