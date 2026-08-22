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
`build/release/extension/ofquack/ofquack.duckdb_extension` (loadable binary).

Single test file: `./build/release/test/unittest test/sql/ofquack.test`.

The C++ suites are registered in the extension's own subdirectory, so the
top-level `ctest` reports zero tests — run them there:

```sh
ctest --test-dir build/release/extension/ofquack
./build/release/extension/ofquack/ofquack_pure_test      # ~1s, no DuckDB, no network
./build/release/extension/ofquack/ofquack_adapter_test   # drives the table function
```

**Type-check without building:** `scripts/syntax_check.sh src/<file>.cpp` runs
`c++ -fsyntax-only` against the pinned DuckDB headers — about a second, versus minutes for a
full rebuild. Use it to iterate on compile errors; it cannot catch link errors.

`scripts/check_windows_view.py` catches POSIX calls that leaked into a Windows branch without
waiting ~40 minutes for the CI matrix.

The SQL tests are a placeholder (`SELECT 1`) — they cannot reach the table function, which needs
live Fusion credentials. Real coverage lives in the two C++ suites above, which is what the
`FusionTransport` seam is for.

## Architecture

The code is cut into layers, and the cut is load-bearing:

- **Layer 1 — pure** (`soap_envelope`, `xml_report`): no DuckDB, no network. Tested by
  `pure_test` in about a second.
- **Layer 2 — transport** (`transport`, `soap_transport`, `http_curl`): knows libcurl, knows
  nothing about DuckDB.
- **Layer 4 — adapter** (`ofquack_extension.cpp`): knows DuckDB, reaches Fusion *only* through
  `FusionTransport`.

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

Table-function wiring: `FusionBind` does all network I/O and materialises the whole result;
`FusionScan` + `FusionLocalState::offset` emit it in `STANDARD_VECTOR_SIZE` chunks.
`init_global` is `nullptr`, so there is no parallelism.

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
connection.Query("SELECT * FROM oracle_fusion_wsdl_query(...)");
```

See `test/cpp/adapter_test.cpp`. Anything that would otherwise need credentials belongs there.

## Extension API notes (v1.5.5)

- `ExtensionUtil` was **removed in v1.4.0**; its header is now a `static_assert(false)` trap.
  Registration goes through `ExtensionLoader`: `loader.RegisterFunction(fn)`,
  `loader.RegisterSecretType(type)`, `loader.SetDescription(...)`.
- Entry point is `DUCKDB_CPP_EXTENSION_ENTRY(ofquack, loader)`. The old `ofquack_init` /
  `ofquack_version` / `ofquack_shutdown` trio no longer exists — which is why
  `curl_global_init` sits behind a `std::once_flag` and there is no paired
  `curl_global_cleanup`: there is no shutdown hook to call it from, and calling it from a static
  destructor would race libcurl's background threads.
- The version string comes from `EXT_VERSION_OFQUACK`, which extension-ci-tools defines from
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

## Known defects being fixed

These are deliberate, pinned by tests that assert today's wrong behaviour so the fix is visible
when it lands. Invert those tests rather than deleting them, and do not "fix" any of this
piecemeal without reading the plan:

- columns come from a `std::set`, so they are alphabetical rather than in SELECT order;
- a SOAP fault yields zero rows instead of an error — the caller cannot tell "no data" from
  "the server refused";
- an empty result guesses column names by slicing the SQL between `SELECT` and `FROM` on commas;
- a column missing from a row becomes an empty string rather than SQL NULL;
- `]]>` in user SQL breaks out of the CDATA section;
- the whole result is materialised during bind: no paging, no streaming.
