# Ofquack — SQL against Oracle Fusion

Oracle Fusion gives you no SQL endpoint. No listener, no `tnsnames.ora`, no
`sqlplus`. If you want to know what is actually in `AP_INVOICES_ALL`, your
options are OTBI, a BI Publisher report you build by hand, or a REST API that
covers a fraction of the schema.

**Ofquack turns that into ordinary SQL.** You write a `SELECT`; it goes to
Fusion inside a BI Publisher web service call, `dbms_xmlgen` runs it, and the
rows come back to your machine as a result set you can join, filter and export.

```sql
SELECT * FROM oracle_fusion_query(
    'SELECT invoice_num, invoice_amount, invoice_date
       FROM AP_INVOICES_ALL
      WHERE vendor_id = 12345'
);
```

Read-only, by construction: there is no write path through BI Publisher.

**[Full function reference →](docs/REFERENCE.md)** — every function, what it
does, and worked examples.

---

## If you have not used DuckDB before

Most of the Fusion people who try this have never touched DuckDB, so here is
the whole of it in a minute.

**DuckDB is a SQL engine that runs inside your own process.** Not a server.
There is no listener to configure, no instance to provision, no DBA to ask, and
nothing is installed on any host but yours. If you know SQLite: DuckDB is
SQLite's idea applied to analytics — columnar, fast at aggregation, and it
reads CSV, Parquet and JSON as if they were tables. A `duckdb` binary is a
single file; download it, run it, and you have a SQL prompt.

**Ofquack is an extension** — DuckDB's word for a plugin. `INSTALL` it once,
`LOAD` it per session, and your DuckDB gains the functions in this document.

**What this means in practice:**

- Everything runs on your laptop. Fusion sees ordinary BI Publisher web service
  calls made as *you*, subject to the same privileges and data security as when
  you sign in through the browser.
- No third party is involved. Nothing is relayed through anyone's cloud.
- The result lands locally, so you can join Fusion data to a spreadsheet, write
  it to Parquet, or feed it to whatever comes next.

**One idiom you will need.** DuckDB functions that return a table are called
by selecting from them:

```sql
SELECT * FROM oracle_fusion_tables();
```

Oracle writes that as `SELECT * FROM TABLE(some_pipelined_function())`. DuckDB
drops the `TABLE()` wrapper. And these functions are not always passive — for
example `SELECT * FROM ofquack_sso_login()` opens a browser and signs you in.
The row it returns afterwards reports what happened; the call is the point. The
[reference](docs/REFERENCE.md) says for each function what it actually does.

---

## Before you start: the report

**This does not work against a stock Fusion instance.** It needs one small
report deployed in your instance, which is what accepts a SQL statement and
runs it.

Take `DM_ARB.xdm.catalog` and `RP_ARB.xdo.catalog` from
[the ofjdbc repository](https://github.com/krokozyab/ofjdbc/tree/master/otbireport)
and un-archive them into `/Shared Folders/Custom/Financials` in BI Publisher
(any folder will do — you pass its path in `REPORT_PATH`).

You need the **BI Publisher Data Model Developer** role to deploy it, and the
account you connect with needs **Access SOAP** and permission to run the
report.

---

## Install

```sql
INSTALL ofquack FROM community;
LOAD ofquack;
```

`INSTALL` downloads it once. `LOAD` is per session — put it at the top of your
script, or in your DuckDB startup file.

> **Going to use `ATTACH` and browse tables in a client?** Do
> [the one-time warm-up](#first-run-warm-the-dictionary) first, or the schema
> will look empty and you will think it is broken.

---

## Your first query

```sql
CREATE SECRET fusion (
    TYPE oracle_fusion,
    ENDPOINT 'https://fa-xxxx-dev1.fa.ocs.oraclecloud.com',
    REPORT_PATH '/Custom/Financials/RP_ARB.xdo',
    USERNAME 'your.name',
    PASSWORD '…'
);

SELECT * FROM oracle_fusion_query(
    'SELECT currency_code, name FROM FND_CURRENCIES_TL WHERE ROWNUM < 10'
);
```

The **secret** is DuckDB's credential store. Keeping the connection there is
the point: passed as function arguments, your password would sit in the SQL
text, in `duckdb_queries()` and in your shell history. `duckdb_secrets()` shows
the secret with the password redacted.

> `CREATE PERSISTENT SECRET` writes `~/.duckdb/stored_secrets` **unencrypted**.
> Redaction hides the password from the catalog view, not from the disk. The
> plain `CREATE SECRET` above lives only for the session.

**Signing in with SSO instead** — if your instance uses Okta, Entra or MFA and
you have no password to give:

```sql
CREATE SECRET fusion (
    TYPE oracle_fusion,
    PROVIDER browser,
    ENDPOINT 'https://fa-xxxx-dev1.fa.ocs.oraclecloud.com',
    REPORT_PATH '/Custom/Financials/RP_ARB.xdo'
);

SELECT * FROM ofquack_sso_login();   -- opens a browser; sign in there
```

That second statement is the sign-in. A browser window opens, you authenticate
however your organisation requires, and the token is kept in memory for the
session. See [SSO](docs/SSO.md).

---

## Two SQL dialects in one statement

This trips people up once, and then never again.

```sql
SELECT count(*)                                  -- ← DuckDB SQL
FROM oracle_fusion_query(
    'SELECT * FROM GL_JE_HEADERS WHERE ROWNUM < 100'   -- ← Oracle SQL
);
```

The **string** is Oracle SQL. It is sent to Fusion and executed by Oracle, so
`ROWNUM`, `NVL`, `TO_DATE`, `CONNECT BY`, optimiser hints and every Oracle
built-in work exactly as they do in Oracle.

**Everything outside the string** is DuckDB SQL — closer to PostgreSQL than to
Oracle. So `LIMIT`, not `ROWNUM`; `NULLIF`/`COALESCE`, not `NVL`; no `DUAL`.

Two practical consequences:

- Doubled quotes inside the string: `WHERE status = ''APPROVED''`. Or use
  DuckDB's dollar quoting — `$$…$$` — and stop escaping altogether.
- Push the work into the Oracle side when it is selective. Filtering in the
  string means fewer rows cross the wire; filtering outside it means Fusion
  sends everything first.

---

## Attaching Fusion as a schema

Passing SQL strings gets tiring. `ATTACH` makes Fusion tables look like tables:

```sql
ATTACH 'fusion' AS f (TYPE oracle_fusion);

SELECT invoice_num, invoice_amount
FROM f.AP_INVOICES_ALL
WHERE vendor_id = 12345;
```

Column types come from Fusion's own dictionary, so `NUMBER(10,2)` arrives as
`DECIMAL` and `DATE` as `DATE`.

### First run: warm the dictionary

> ⚠️ **Attach without warming and the schema looks empty.** Expand it in
> DBeaver and there are no tables. Nothing is broken — the catalog shows only
> what it already knows, and on a fresh install it knows nothing.

Run this once, before you attach anything. It takes **minutes**, it makes tens
of requests, and you never do it again on this machine:

```sql
LOAD ofquack;

-- 1. The names. Tens of thousands of them, cached on disk for a week.
SELECT count(*) FROM oracle_fusion_tables();

-- 2. The columns, for the tables you actually care about.
--    Without this step the tree stays empty even though step 1 succeeded.
SELECT * FROM ofquack_cache_warm(pattern := 'AP\_%',  max_tables := 500);
SELECT * FROM ofquack_cache_warm(pattern := 'GL\_%',  max_tables := 500);
SELECT * FROM ofquack_cache_warm(pattern := 'XLA\_%', max_tables := 500);
```

Then attach, and the tables are there — instantly, in this session and every
session after it.

Two things are worth separating, because they fail differently:

| | Cold | After warming |
|---|---|---|
| `ATTACH` | instant, no requests | instant |
| `SHOW TABLES`, the DBeaver tree, autocomplete | **empty** — never asks Fusion | lists the warmed tables |
| `SELECT … FROM f.AP_INVOICES_ALL` | works, but the **first one pays for the whole dictionary listing** — minutes | seconds |

So a table you name directly always works, listed or not. It is the *browsing*
that needs warming — and the first query on a cold machine that is unexpectedly
slow, because it is doing step 1 for you in the middle of your `SELECT`.

Warming both steps deliberately, up front, is the difference between "this is
broken" and "this is a database".

**Why it is not automatic:** a Fusion instance holds tens of thousands of
objects, and fetching every table's columns is hours of SOAP calls. Which
families you need is your decision, not one this extension should make for you.
`ofquack_cache_status()` shows what is currently cached.

**Which to use.** `ATTACH` for browsing and for straightforward reads;
`oracle_fusion_query` when you want Oracle to do the work — a join, an analytic
function, a hint. The [reference](docs/REFERENCE.md#when-to-use-attach-and-when-to-use-oracle_fusion_query)
has the comparison.

---

## What to expect from it

**It is a report, not a connection.** Every request opens a BI Publisher
session, takes seconds, and leaves a session behind on the server. That single
fact explains most of the design:

- requests to one instance are **serialised** — a few parallel scans would
  otherwise leave hundreds of sessions behind;
- results are **paged**, and a page is a request;
- dictionary answers are **cached on disk** for a week, because asking again
  costs minutes;
- transient failures are **retried** with backoff, and an instance that keeps
  failing trips a breaker instead of being hammered.

**Speed, honestly.** A small query is a few seconds. Reading a million-row
table is bounded by the number of round trips — raise `FETCH_SIZE` to make
fewer of them, and expect minutes. This is the shape of the channel, not
something a future version fixes.

**Large tables:** an attached table is read by seeking on its key, so every
page costs the same however deep you are. Through `oracle_fusion_query`, give
your statement its own `ORDER BY` on an indexed key — otherwise the extension
has to add one over every column so that pages do not overlap, and Oracle
sorts the whole result before the first page arrives.

More detail: [capabilities and limits](docs/CAPABILITIES.md).

---

## Documentation

| | |
|---|---|
| [**Function reference**](docs/REFERENCE.md) | Every function and setting, what it does, examples |
| [SSO](docs/SSO.md) | The browser sign-in flow |
| [Metadata and caching](docs/METADATA.md) | Where the dictionary comes from, and why it is cached |
| [Capabilities and limits](docs/CAPABILITIES.md) | What works, what does not, and why |
| [Updating](docs/UPDATING.md) | Moving to a new DuckDB version |

---

## Troubleshooting

**The attached schema is empty — no tables in the tree** — the dictionary has
not been warmed on this machine. See
[warm the dictionary first](#first-run-warm-the-dictionary). Note
that `oracle_fusion_tables()` alone is not enough: a table appears in the
listing only once its *columns* are cached, which is what `ofquack_cache_warm()`
does. `SELECT * FROM ofquack_cache_status()` shows where you are.

**The first query on a new machine takes minutes** — the same cause. Naming a
table on a cold cache pays for the whole dictionary listing inside your
`SELECT`. Warm deliberately and it happens once, visibly, instead of
unexpectedly.

**"Oracle Fusion redirected the request to a sign-in page"** — the credentials
were not accepted, or the instance uses SSO and you have not run
`ofquack_sso_login()`.

**"redirected the SOAP request to … a page of the application"** — the request
reached Fusion but was not treated as a web service call. Check that the
account has **Access SOAP** and can open BI Publisher.

**"Oracle Fusion returned no rows, so the result has no columns"** — a result
with no rows has no schema to describe. Add a predicate that matches something.

**A query that used to work now fails after you rebuilt the extension** — check
`SELECT ofquack_version()`. The build timestamp tells you whether your client
is still holding the previous binary in memory; if it is, restart it.

**A table "does not exist" that plainly does** — `oracle_fusion_columns('THE_TABLE')`
will say whether the dictionary knows it. If the dictionary listing was cached
while incomplete, `SELECT * FROM oracle_fusion_tables(refresh := true)`.

---

## Building from source

Dependencies (libcurl, OpenSSL, tinyxml2) come from vcpkg:

```sh
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

Built against DuckDB **v1.5.5**. A loadable extension refuses to load into any
other version, so the `duckdb` submodule, the `extension-ci-tools` submodule
and `duckdb_version` in the CI workflow have to move together.

Loading a locally built binary needs unsigned extensions allowed:

```sh
./build/release/duckdb -unsigned -c "LOAD './build/release/extension/ofquack/ofquack.duckdb_extension'"
```

### Tests

Three suites, in increasing order of cost. None of them needs a network or
credentials:

```sh
# Pure unit tests: no DuckDB at all, about a second.
cmake -S test/standalone -B build/pure -G Ninja && cmake --build build/pure
./build/pure/ofquack_pure_test

# Adapter tests: drive the table functions and the catalog against a scripted
# transport.
./build/release/extension/ofquack/ofquack_adapter_test

# SQL tests.
make test
```

Anything that would otherwise need a live instance belongs in
`test/cpp/adapter_test.cpp`, which swaps the transport for a scripted one.

---

## Credits

The Fusion detour, the report, the dictionary queries and the browser sign-in
flow come from [ofjdbc](https://github.com/krokozyab/ofjdbc), the JDBC driver
for the same problem. Use that one if you want a driver for a JDBC tool; use
this one if you want DuckDB.

Built on the [DuckDB extension template](https://github.com/duckdb/extension-template).
