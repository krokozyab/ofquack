# This file is included by DuckDB's build system. It specifies which extension to load

# Extension from this repo
duckdb_extension_load(fusion_scanner
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}
    LOAD_TESTS
    EXTENSION_VERSION 0.3.1
)

# Any extra extensions that should be built
# e.g.: duckdb_extension_load(json)

# DuckDB 2.0 builds an extension and links it as separate decisions: one that is
# only loaded is built, not linked into unittest or the adapter test. Ask for the
# link where the function exists, together with core_functions, which holds
# list_value and the rest of what 1.5 linked by default. On 1.5 every loaded
# extension is linked anyway, and the function does not exist.
if(COMMAND duckdb_extension_statically_link)
    duckdb_extension_statically_link(fusion_scanner core_functions)
endif()
