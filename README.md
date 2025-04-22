# Ofquack Extension for DuckDB

This repository is based on https://github.com/duckdb/extension-template, check it out if you want to build and ship your own DuckDB extension.

---

The **Ofquack** extension provides seamless integration between DuckDB and Oracle Fusion via WSDL-based SOAP calls. It allows you to run arbitrary SQL queries against Oracle Fusion database directly from DuckDB, inferring column names at runtime and returning all data as VARCHAR columns—as native DuckDB tables and as resultsets that can be directly consumed by downstream applications.

---
## Features

**Dynamic Schema Inference:** Automatically parses XML report output, inferring column names at runtime (all columns returned as VARCHAR).

**Table Function Interface:** Exposes a simple table function oracle_fusion_wsdl_query(...) in DuckDB CLI and clients.

**Credential Handling: Securely** sends Basic‑auth credentials over SOAP.

**Chunked Results:** Efficiently streams large result sets in vectorized chunks.

**Uniform VARCHAR Output:** All columns are returned as VARCHAR. Any further type conversion (e.g., to INTEGER, DATE, DECIMAL) should be performed by the recipient SQL client or query after fetching the data.

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
Call the table function:
```
SELECT *
FROM oracle_fusion_wsdl_query(
    'https://<your‑host>/xmlpserver/services/ExternalReportWSSService?WSDL',
    '<username>',
    '<password>',
    '/Custom/Financials/RP_ARB.xdo',
    'SELECT currency_code, name, description FROM FND_CURRENCIES_TL WHERE rownum<10'
);
```

## Function Signature
```
oracle_fusion_wsdl_query(
    endpoint VARCHAR,  -- WSDL URL
    username VARCHAR,  -- Oracle Fusion user
    password VARCHAR,  -- Oracle Fusion password
    report_path VARCHAR, -- Report absolute path
    sql VARCHAR        -- SQL to embed in the report
) RETURNS TABLE(<dynamic_columns> VARCHAR...)
```
**endpoint:** Full WSDL endpoint URL for Oracle Fusion PublicReportService.

**username/password:** Credentials e.g. user@example.com / MySecretPass123.

**report_path:** Oracle report path (e.g. /Custom/Financials/RP_ARB.xdo).

**sql:** The inner SQL query to run.

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
