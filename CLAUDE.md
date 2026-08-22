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

**Type-check without building:** `scripts/syntax_check.sh src/<file>.cpp` runs
`c++ -fsyntax-only` against the pinned DuckDB headers — about a second, versus minutes for a
full rebuild. Use it to iterate on compile errors; it cannot catch link errors.

`scripts/check_windows_view.py` catches POSIX calls that leaked into a Windows branch without
waiting ~40 minutes for the CI matrix.

Note: the SQL tests are placeholders — they cannot exercise the table function, which needs live
Fusion credentials. Real coverage depends on the `FusionTransport` seam (see below).

## Architecture

Everything currently lives in `src/ofquack_extension.cpp`, as a linear pipeline of free
functions numbered 1–9 in comments:

1. `BuildEnvelope` — hand-writes the SOAP `runReport` envelope, embedding the user SQL as CDATA
   in the `p_sql` parameter, `sizeOfDataChunkDownload=-1` (whole payload in one response).
2. `FetchSoap` — libcurl POST with Basic auth (base64 from `src/base64.cpp`, vendored).
3. `ExtractReportXML` — tinyxml2 walk to find `<reportBytes>` by *local* name (namespace
   prefixes are stripped everywhere, since Fusion's prefixes vary), then base64-decode.
4. `ParseRows` — the decoded payload contains `<RESULT>` elements whose *text content* is
   another escaped XML document (`<ROWSET><ROW>…`), so each is re-parsed as a nested document.

Table-function wiring: `fuse_bind` does all network I/O and materialises the entire result;
`fuse_func` + `FusionLocalState::offset` emit it in `STANDARD_VECTOR_SIZE` chunks.
`init_global` is `nullptr`, so there is no parallelism.

`tinyxml2` is aliased as `tx2` to avoid a symbol collision with MSXML on Windows — keep it.

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

Tracked in the plan; do not "fix" them piecemeal without reading it:
columns collected into a `std::set` (alphabetical order instead of SELECT order);
SOAP faults swallowed to stderr with 0 rows returned; debug output in the bind phase;
column-name fallback that slices the SQL between `SELECT` and `FROM` on commas;
`]]>` in user SQL breaking the CDATA section.
