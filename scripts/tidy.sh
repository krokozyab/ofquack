#!/usr/bin/env bash
# Run clang-tidy over this extension's own sources, with DuckDB's own configuration.
#
# Why not `make tidy-check` from extension-ci-tools: that target configures the
# whole of DuckDB with -DCLANG_TIDY=1, which needs every dependency this
# extension declares in vcpkg.json -- and the reusable code-quality workflow
# never sets vcpkg up, so the configure fails on `find_package(tinyxml2)` before
# clang-tidy runs at all. Its file filter is `<project>/src/.*/`, which does not
# match a flat `src/*.cpp` layout either, so even a successful configure would
# have checked nothing.
#
# This runs the checker directly instead: no compile database, no DuckDB build,
# about a minute. `WarningsAsErrors: '*'` in duckdb/.clang-tidy makes any
# enabled check a failure, which is the intent.
#
# Usage: scripts/tidy.sh [file.cpp ...]   (defaults to every source it owns)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DUCKDB="$ROOT/duckdb"

if [[ ! -f "$DUCKDB/.clang-tidy" ]]; then
	echo "duckdb submodule is not checked out: run git submodule update --init" >&2
	exit 1
fi

TIDY="${CLANG_TIDY:-}"
if [[ -z "$TIDY" ]]; then
	for candidate in clang-tidy /opt/homebrew/opt/llvm/bin/clang-tidy /usr/bin/clang-tidy; do
		if command -v "$candidate" >/dev/null 2>&1; then
			TIDY="$candidate"
			break
		fi
	done
fi
if [[ -z "$TIDY" ]]; then
	echo "clang-tidy not found; set CLANG_TIDY to its path" >&2
	exit 1
fi

INCLUDES=(
	-I"$ROOT/src/include"
	-I"$DUCKDB/src/include"
	-I"$DUCKDB/third_party/fmt/include"
	-I"$DUCKDB/third_party/re2"
	-I"$DUCKDB/third_party/utf8proc/include"
	-I"$DUCKDB/third_party/fast_float"
	-I"$DUCKDB/third_party/concurrentqueue"
	-I"$DUCKDB/third_party/hyperloglog"
	-I"$DUCKDB/third_party/yyjson/include"
	-I"$DUCKDB/third_party/miniz"
)

# vcpkg-provided headers (tinyxml2, curl) from a local build tree, if there is one.
for dir in "$ROOT"/build/*/vcpkg_installed/*/include; do
	[[ -d "$dir" ]] && INCLUDES+=(-I"$dir")
done
if [[ -n "${VCPKG_ROOT:-}" ]]; then
	for dir in "$VCPKG_ROOT"/installed/*/include; do
		[[ -d "$dir" ]] && INCLUDES+=(-I"$dir")
	done
fi

# base64.cpp is vendored verbatim from https://github.com/ReneNyffenegger/cpp-base64.
# Its style is not ours to change, and rewriting it would make the next update a
# merge instead of a copy.
sources=("$@")
if [[ ${#sources[@]} -eq 0 ]]; then
	while IFS= read -r file; do
		[[ "$(basename "$file")" == "base64.cpp" ]] && continue
		sources+=("$file")
	done < <(find "$ROOT/src" -maxdepth 1 -name '*.cpp' | sort)
fi

failed=0
for source in "${sources[@]}"; do
	echo "==> $(basename "$source")"
	# -header-filter overrides HeaderFilterRegex in duckdb/.clang-tidy, which points
	# at DuckDB's own headers: without it every diagnostic in duckdb/src/include
	# is reported as ours.
	"$TIDY" --config-file="$DUCKDB/.clang-tidy" --header-filter="$ROOT/src/include/ofquack/.*" \
		--quiet "$source" -- \
		-std=c++17 -xc++ "${INCLUDES[@]}" || failed=1
done

if [[ $failed -ne 0 ]]; then
	echo "clang-tidy reported findings" >&2
	exit 1
fi
echo "clang-tidy: clean"
