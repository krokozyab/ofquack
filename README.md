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
  calls made as *you*: the report runs under your credentials, and Fusion checks
  that you are allowed to run it. That is authentication and function security.
  It is **not** the row-level data security you get on a Fusion page — a report
  that runs arbitrary SQL against base tables does not inherit it. Read
  [the security notes](docs/CAPABILITIES.md#security-notes) before pointing this
  at a production instance.
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
example `SELECT * FROM fusion_scanner_sso_login()` opens a browser and signs you in.
The row it returns afterwards reports what happened; the call is the point. The
[reference](docs/REFERENCE.md) says for each function what it actually does.

---

## Before you start: the report

**This does not work against a stock Fusion instance.** It needs one small
report deployed in your instance — that report is what accepts a SQL statement
and runs it.

> **Already using ofjdbc? Skip this step.**
>
> It is the **same report**. [ofjdbc](https://github.com/krokozyab/ofjdbc) is
> the JDBC driver for this same detour, by the same author, and this extension
> talks to the report it deploys. If your DBeaver already connects through
> ofjdbc, the Fusion side is done — use the same path you have in your JDBC
> URL as `REPORT_PATH` here, and go straight to [Install](#install).

Otherwise, deploy it once. From
[the `otbireport` folder of the ofjdbc repository](https://github.com/krokozyab/ofjdbc/tree/master/otbireport):

> Setup Fusion Reports: In your Fusion instance, un-archive
> `DM_ARB.xdm.catalog` and `RP_ARB.xdo.catalog` (found in the `otbireport`
> folder of this repository) into the `/Shared Folders/Custom/Financials`
> folder. Note: You can use a different folder path, but you will need to
> update the report path in the connection URL.

Here, "the report path" is the `REPORT_PATH` on your secret — for the folder
above, `/Custom/Financials/RP_ARB.xdo`.

Deploying a data model needs BI Publisher privileges in Fusion; the account you
then connect with needs **Access SOAP** and permission to run the report. If it
lacks either, the error says so by name.

---

## Install

```sql
INSTALL fusion_scanner FROM community;
LOAD fusion_scanner;
```

`INSTALL` downloads it once. `LOAD` is per session — put it at the top of your
script, or in your DuckDB startup file.

> **Going to use `ATTACH` and browse tables in a client?** Load
> [the table list once](#first-run-load-the-table-list) first, or the schema will look
> empty and you will think it is broken.

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

SELECT * FROM fusion_scanner_sso_login();   -- opens a browser; sign in there
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
`DECIMAL`. Two mappings are worth knowing before you total a column:

- Oracle's `DATE` carries a time of day, so it arrives as `TIMESTAMP`. DuckDB's
  `DATE` would drop half of it.
- A `NUMBER` that declares neither precision nor scale — which is how Fusion
  declares its amount columns, `GL_JE_LINES.ENTERED_DR` among them — arrives as
  `DOUBLE`. There is no declared scale for `DECIMAL` to use, and the only one
  available would round every amount to a whole number. `DOUBLE` cannot hold all
  38 digits Oracle allows, so an unconstrained `NUMBER` used as a wide
  identifier loses its low digits past 2^53. `number_mode := 'decimal'` gives
  `DECIMAL(38,6)` instead, and `'text'` gives up nothing at all;
  `SELECT * FROM oracle_fusion_columns('…') WHERE lossy` lists the columns where
  the choice matters.

A value that turns out not to fit its column reads as NULL. Pass
`on_cast_error := 'error'` to have the query fail and name it instead.

### First run: load the table list

> ⚠️ **Attach before loading the list and the schema looks empty.** Expand it in
> DBeaver and there are no tables. Nothing is broken — the catalog is answered
> from the cache, and on a fresh install the cache is empty.

One statement fixes it:

```sql
LOAD fusion_scanner;

SELECT * FROM oracle_fusion_tables();
```

That fetches every table and view in the instance and saves the list to
`~/.fusion_scanner/metadata.duckdb`. It takes seconds; later runs read the file.
After it, an attached catalog lists **all of them** and every query that names a
table works.

Columns are not part of the list and do not need to be: a table's columns are
fetched the first time it is queried, and cached with it. So you pay once for
the list, and after that only for the tables you actually read.

| | Before the list is loaded | After |
|---|---|---|
| `ATTACH` | instant | instant |
| `SHOW TABLES`, DBeaver tree | empty | every table and view |
| `SELECT … FROM f.AP_INVOICES_ALL` | loads the list, then this table's columns | this table's columns |
| the same query again | — | no requests |

**One wrinkle in the tree.** A table that is listed but has never been queried
carries a placeholder column until it is. Expanding it in a client shows that
placeholder rather than its real columns; querying it once replaces them.
DuckDB reads a table's column list without any hook the extension could use to
fetch it first, so listing a name and describing it cannot both be lazy.

Nothing expires by age. `oracle_fusion_tables(refresh := true)` refetches the
list, and deleting `~/.fusion_scanner/metadata.duckdb` clears everything.
`fusion_scanner_cache_status()` shows what is cached.

## What to expect from it

**It is a report, not a connection.** Every request opens a BI Publisher
session, takes seconds, and leaves a session behind on the server. That single
fact explains most of the design:

- requests to one instance are **serialised** — a few parallel scans would
  otherwise leave hundreds of sessions behind;
- results are **paged**, and a page is a request;
- dictionary answers are **cached on disk** and do not expire, because asking
  again repeats seconds-long SOAP calls;
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

**The attached schema is empty — no tables in the tree** — the table list has
not been loaded on this machine yet. `SELECT * FROM oracle_fusion_tables();`
once, and the tree fills with every table and view.
`fusion_scanner_cache_status()` shows what is cached.

**The first query on a new machine is unexpectedly slow** — naming a table on a
cold cache first builds the name index inside your `SELECT`. Run
`oracle_fusion_tables()` deliberately and it happens once, visibly, instead of
inside an unrelated query.

**"Oracle Fusion redirected the request to a sign-in page"** — the credentials
were not accepted, or the instance uses SSO and you have not run
`fusion_scanner_sso_login()`.

**"redirected the SOAP request to … a page of the application"** — the request
reached Fusion but was not treated as a web service call. Check that the
account has **Access SOAP** and can open BI Publisher.

**"Oracle Fusion returned no rows, so the result has no columns"** — a result
with no rows has no schema to describe. Add a predicate that matches something.

**A query that used to work now fails after you rebuilt the extension** — check
`SELECT fusion_scanner_version()`. The build timestamp tells you whether your client
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
- `./build/release/extension/fusion_scanner/fusion_scanner.duckdb_extension` — the loadable binary
- `./build/release/test/unittest` — DuckDB's test runner

Built against DuckDB **v1.5.5**. A loadable extension refuses to load into any
other version, so the `duckdb` submodule, the `extension-ci-tools` submodule
and `duckdb_version` in the CI workflow have to move together.

Loading a locally built binary needs unsigned extensions allowed:

```sh
./build/release/duckdb -unsigned -c "LOAD './build/release/extension/fusion_scanner/fusion_scanner.duckdb_extension'"
```

### Tests

Three suites, in increasing order of cost. None of them needs a network or
credentials:

```sh
# Pure unit tests: no DuckDB at all, about a second.
cmake -S test/standalone -B build/pure -G Ninja && cmake --build build/pure
./build/pure/fusion_scanner_pure_test

# Adapter tests: drive the table functions and the catalog against a scripted
# transport.
./build/release/extension/fusion_scanner/fusion_scanner_adapter_test

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
