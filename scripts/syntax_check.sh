#!/usr/bin/env bash
# Type-check one source file against the pinned DuckDB headers without building.
#
# A full `make` rebuilds DuckDB and takes minutes; this takes about a second, so
# an API migration can be iterated file by file. It only parses and type-checks
# -- it emits no object code, so a clean run here is necessary but not
# sufficient: link errors still need a real build.
#
# Usage: scripts/syntax_check.sh src/ofquack_extension.cpp [more.cpp ...]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DUCKDB="$ROOT/duckdb"

if [[ ! -f "$DUCKDB/src/include/duckdb.hpp" ]]; then
	echo "duckdb submodule is not checked out: run git submodule update --init" >&2
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

# vcpkg-provided headers (tinyxml2, curl) when a local vcpkg tree exists.
for triplet in arm64-osx x64-osx x64-linux arm64-linux; do
	candidate="$ROOT/build/release/vcpkg_installed/$triplet/include"
	[[ -d "$candidate" ]] && INCLUDES+=(-I"$candidate")
done
if [[ -n "${VCPKG_ROOT:-}" && -d "$VCPKG_ROOT/installed" ]]; then
	for dir in "$VCPKG_ROOT"/installed/*/include; do
		[[ -d "$dir" ]] && INCLUDES+=(-I"$dir")
	done
fi

status=0
for file in "$@"; do
	echo "==> $file"
	c++ -std=c++17 -fsyntax-only -ferror-limit=0 \
		"${INCLUDES[@]}" "$file" || status=1
done
exit $status
