# Ofquack Extension for DuckDB

This repository is based on https://github.com/duckdb/extension-template, check it out if you want to build and ship your own DuckDB extension.

---

The **Ofquack** extension provides seamless integration between DuckDB and Oracle Fusion via WSDL-based SOAP calls. It allows you to run arbitrary SQL queries against Oracle Fusion database directly from DuckDB, inferring column names at runtime and returning all data as VARCHAR columns—as native DuckDB tables and as resultsets that can be directly consumed by downstream applications.

---
## Features

**Dynamic Schema Inference:** Automatically parses XML report output, inferring column names at runtime (all columns returned as VARCHAR).

**Table Function Interface:** Exposes a simple table function oracle_fusion_query(...) in DuckDB CLI and clients.

**Credential Handling: Securely** sends Basic‑auth credentials over SOAP.

**Chunked Results:** Efficiently streams large result sets in vectorized chunks.

**Inferred Column Types:** Numbers, dates and timestamps come back as native DuckDB types, inferred from the data; `all_varchar := true` returns everything as VARCHAR instead.

**Paging:** Large results are fetched a page at a time, so a wide table does not have to fit in one SOAP response.

**Credentials in secrets:** The connection lives in a DuckDB secret, so passwords stay out of SQL text and query history.

**Resilient:** Transient failures are retried with exponential backoff; a failing instance trips a circuit breaker instead of being hammered.

Column order follows the SELECT list, and a column that Oracle returned as NULL arrives as SQL NULL rather than an empty string.

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
    ENDPOINT 'https://<your-host>/xmlpserver/services/ExternalReportWSSService?WSDL',
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
| `endpoint` | WSDL endpoint URL. |
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

### Errors

A SOAP fault, a permissions problem or a bad table name now raise an error
carrying the `ORA-` code, instead of quietly returning zero rows — previously
a typo in a table name was indistinguishable from a query that matched nothing.

A query that returns no rows is also an error: the result carries no columns,
so its schema is unknown. Add a predicate that matches at least one row, or
wrap the query so that it always returns one.

## Building
### Managing dependencies
DuckDB extensions uses VCPKG for dependency management. Enabling VCPKG is very simple: follow the [installation instructions](https://vcpkg.io/en/getting-started) or just run the following:
```shell
git clone https://github.com/Microsoft/vcpkg.git
./vcpkg/bootstrap-vcpkg.sh
export VCPKG_TOOLCHAIN_PATH=`pwd`/vcpkg/scripts/buildsystems/vcpkg.cmake
```
Note: VCPKG is only required for extensions that want to rely on it for dependency management. If you want to develop an extension without dependencies, or want to do your own dependency management, just skip this step. Note that the example extension uses VCPKG to build with a dependency for instructive purposes, so when skipping this step the build may not work without removing the dependency.

### Build steps
Now to build the extension, run:
```sh
make
```
The main binaries that will be built are:
```sh
./build/release/duckdb
./build/release/test/unittest
./build/release/extension/ofquack/ofquack.duckdb_extension
```
- `duckdb` is the binary for the duckdb shell with the extension code automatically loaded.
- `unittest` is the test runner of duckdb. Again, the extension is already linked into the binary.
- `ofquack.duckdb_extension` is the loadable binary as it would be distributed.

## Running the extension
To run the extension code, simply start the shell with `./build/release/duckdb`.

Now we can use the features from the extension directly in DuckDB. 

## Running the tests
Different tests can be created for DuckDB extensions. The primary way of testing DuckDB extensions should be the SQL tests in `./test/sql`. These SQL tests can be run using:
```sh
make test
```

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
