# Moving to a new DuckDB release

The extension is built against DuckDB's **internal C++ API**, which is not
stable between releases. A loadable extension also refuses to load into any
DuckDB other than the one it was built against, so the version is not a detail
that can drift.

Currently: DuckDB **2.0 pre-release**, commit `b15358c3` tagged
`v2.0.0-alpha46057` on the `v2.0-cyanoptera` branch, extension-ci-tools
**v2.0-cyanoptera**. That pair is exactly what the community registry's
`build.yml` builds `ref` against; pin the commit, not the branch, which moves
daily and takes the internal API with it. The 1.5 line lives on `main`
(v1.5.5) and reaches the registry through `repo.variegata`, built against
v1.5.6.

## Four pins that must move together

1. The `duckdb` submodule → the new tag.
2. The `extension-ci-tools` submodule → the matching branch. It is named after
   the release's codename, not its number: `v1.5-variegata` for the 1.5 line,
   `v1.4-andium` for 1.4. Confirm with
   `git ls-remote --heads https://github.com/duckdb/extension-ci-tools`.
3. `duckdb_version` and `ci_tools_version` in **every** job of
   `.github/workflows/MainDistributionPipeline.yml`, including the deploy job.
4. The `@`-ref of each reusable workflow in that file.

`.gitmodules` names the branches too, so that `git submodule update --remote`
does not quietly drag both back to `main`.

A mismatch between (1) and (3) produces a build failure that says nothing about
versions, so check all four before debugging anything else.

## Then fix the compile errors

Do **not** start with `make`: rebuilding DuckDB to discover a typo costs
minutes each time. Type-check one file at a time instead:

```sh
scripts/syntax_check.sh src/fusion_catalog.cpp
```

That runs `c++ -fsyntax-only` against the new headers and takes about a second.
Work through the files, then do a full build for the link errors it cannot see.

## What has broken before

- **v1.4.0 removed `ExtensionUtil`.** Its header is now a `static_assert(false)`
  naming the PR. Registration moved to `ExtensionLoader`, and the entry point
  from `<name>_init` to `DUCKDB_CPP_EXTENSION_ENTRY`. This was most of the cost
  of the v1.2.1 → v1.5.5 migration.
- **Names became `Identifier` on `main`** (the 2.0 track) where v1.5.x uses
  `string`: `table_function_bind_t`, `DefaultGenerator::GetDefaultEntries`,
  `CreateTableInfo`. Anything copied from a `main`-targeting extension needs
  adjusting.
- **`SetChildCardinality` exists on `main` and not on v1.5.5.** On `main` a
  vector carries its own size and a scan that does not set it emits NULLs that
  read as values — visible only on a streaming result, not a materialised one.
- **Within the 2.0 pre-release, `get_bind_info` stopped naming the table.**
  `BindInfo` lost its `TableCatalogEntry` constructor between `2866f801` and
  `b15358c3`; a scan now says which table it reads through
  `TableFunction::get_table_entry`, which is what `LogicalGet::GetTable()` asks.
  A pre-release branch breaks the internal API between commits, not only
  between releases.

The weekly `DuckDB next` workflow compiles against `main` and reports the error
count per file, so the size of the next gap is known before the release lands
rather than after.

## Useful references

- DuckDB [release notes](https://github.com/duckdb/duckdb/releases)
- The git history of the header whose API changed
- [Core extension patches](https://github.com/duckdb/duckdb/commits/main/.github/patches/extensions),
  which show how DuckDB itself fixed the same breakage in its own extensions

## Releasing

1. Bump `EXTENSION_VERSION` in `extension_config.cmake`.
2. Tag `vX.Y.Z`. Nothing is published from the tag: there is no deploy job,
   because the community registry builds and serves the binaries itself.
3. For the community channel, open a PR against
   `duckdb/community-extensions` updating `extensions/fusion_scanner/description.yml`:
   the new `version`, and `ref` set to the **commit SHA** of the release — not
   a tag, which can be moved. That commit must already have the `duckdb`
   submodule on the version named in this file.

The registry picks a ref per DuckDB line (`scripts/build.py` there): `ref`
for the version its `build.yml` defaults to (2.0 now), `variegata` for
v1.5.6, `andium` for v1.4.5, and `ref_next` for anything newer than the
default. A line without its own key builds `ref`, which for a C++ extension
fails: a 2.0 commit does not compile against 1.5.

`docs/community-extension-description.yml` holds the file to copy.
