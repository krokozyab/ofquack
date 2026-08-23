cmake_minimum_required(VERSION 3.5)

# Set extension name here
set(TARGET_NAME fusion_scanner)

# DuckDB's extension distribution supports vcpkg. As such, dependencies can be added in ./vcpkg.json and then
# used in cmake with find_package. Feel free to remove or replace with other dependencies.
# Note that it should also be removed from vcpkg.json to prevent needlessly installing it..
find_package(OpenSSL REQUIRED)
# Require tinyxml2 for XML parsing
find_package(tinyxml2 REQUIRED)
# Find libcurl for SOAP HTTP calls
find_package(CURL REQUIRED)

set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})

# The C++ standard is set per target, with target_compile_features below, and
# deliberately not here. CMAKE_CXX_STANDARD is a cache variable DuckDB owns and
# sets to 11; raising it from an extension raises it for DuckDB's own targets
# too, and only for those configured after this point. That produces a build
# where some translation units are C++11 and some are C++17, which is not a
# style question: `static constexpr` members are implicitly inline from C++17,
# so the two halves emit a strong and a weak definition of the same symbol and
# the link fails on ELF with "multiple definition of
# duckdb::BufferedFileWriter::DEFAULT_OPEN_FLAGS". macOS links it anyway, so
# this only ever shows up on Linux CI.

include_directories(src/include)

set(EXTENSION_SOURCES
        src/fusion_scanner_extension.cpp
        src/fusion_secret.cpp
        src/fusion_connection.cpp
        src/fusion_query_function.cpp
        src/metadata_functions.cpp
        src/fusion_catalog.cpp
        src/fusion_filter.cpp
        src/proc.cpp
        src/jwt.cpp
        src/token_cache.cpp
        src/websocket.cpp
        src/json_util.cpp
        src/browser_auth.cpp
        src/sso_functions.cpp
        src/soap_envelope.cpp
        src/xml_report.cpp
        src/error_decoder.cpp
        src/sql_text.cpp
        src/sql_rewrite.cpp
        src/type_inference.cpp
        src/oracle_type_map.cpp
        src/secured_views.cpp
        src/metadata_queries.cpp
        src/metadata_fetch.cpp
        src/metadata_cache.cpp
        src/retry.cpp
        src/circuit_breaker.cpp
        src/host_throttle.cpp
        src/transport.cpp
        src/soap_transport.cpp
        src/http_curl.cpp
        src/base64.cpp
)

# fusion_scanner_version() embeds __DATE__ and __TIME__, which are fixed when *that*
# file is compiled -- so editing any other source left the reported timestamp
# unchanged, and the function meant to prove a binary is fresh instead argued
# that it was stale. Rebuilding it whenever any source changes makes the stamp
# mean what it claims.
# Absolute paths: OBJECT_DEPENDS resolves a relative one against the build
# directory, where these do not exist.
set(FUSION_SCANNER_STAMP_DEPENDS "")
foreach(fusion_scanner_source ${EXTENSION_SOURCES})
  if(NOT fusion_scanner_source STREQUAL "src/fusion_scanner_extension.cpp")
    list(APPEND FUSION_SCANNER_STAMP_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/${fusion_scanner_source}")
  endif()
endforeach()
set_property(SOURCE src/fusion_scanner_extension.cpp APPEND PROPERTY OBJECT_DEPENDS ${FUSION_SCANNER_STAMP_DEPENDS})

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

# PRIVATE, so the requirement does not propagate to DuckDB's own targets. See
# the comment above project() for why CMAKE_CXX_STANDARD must not be used here.
target_compile_features(${EXTENSION_NAME} PRIVATE cxx_std_17)
target_compile_features(${LOADABLE_EXTENSION_NAME} PRIVATE cxx_std_17)

# Link OpenSSL in both the static library as the loadable extension
target_link_libraries(${EXTENSION_NAME} OpenSSL::SSL OpenSSL::Crypto)
# Link tinyxml2 into the static extension
target_link_libraries(${EXTENSION_NAME} tinyxml2::tinyxml2)
# Link libcurl into the static extension
target_link_libraries(${EXTENSION_NAME} CURL::libcurl)
target_link_libraries(${LOADABLE_EXTENSION_NAME} OpenSSL::SSL OpenSSL::Crypto)
# Link tinyxml2 into the loadable extension
target_link_libraries(${LOADABLE_EXTENSION_NAME} tinyxml2::tinyxml2)
# Link libcurl into the loadable extension
target_link_libraries(${LOADABLE_EXTENSION_NAME} CURL::libcurl)

option(FUSION_SCANNER_BUILD_TESTS "Build the fusion_scanner C++ unit tests" ON)
if(FUSION_SCANNER_BUILD_TESTS)
  enable_testing()

  # The pure suite links neither DuckDB nor libcurl: it covers envelope
  # construction and report parsing only, so it builds and runs in about a
  # second and is cheap enough for every push.
  add_executable(fusion_scanner_pure_test
                 test/cpp/pure_test.cpp
                 src/soap_envelope.cpp
                 src/xml_report.cpp
                 src/error_decoder.cpp
                 src/sql_text.cpp
                 src/sql_rewrite.cpp
                 src/type_inference.cpp
                 src/oracle_type_map.cpp
                 src/secured_views.cpp
                 src/metadata_queries.cpp
                 src/jwt.cpp
                 src/token_cache.cpp
                 src/json_util.cpp
                 src/websocket.cpp
                 src/browser_auth.cpp
                 src/proc.cpp
                 src/http_curl.cpp
                 src/retry.cpp
                 src/circuit_breaker.cpp
                 src/host_throttle.cpp
                 src/base64.cpp)
  target_link_libraries(fusion_scanner_pure_test PRIVATE tinyxml2::tinyxml2 OpenSSL::SSL OpenSSL::Crypto CURL::libcurl)
  target_include_directories(fusion_scanner_pure_test PRIVATE src src/include)
  target_compile_features(fusion_scanner_pure_test PRIVATE cxx_std_17)
  add_test(NAME fusion_scanner_pure_test COMMAND fusion_scanner_pure_test)

  # The adapter suite links DuckDB so it can drive the table function against a
  # transport installed through ScopedTransportFactory, with no database file
  # and no network. duckdb_static is defined later in the DuckDB tree than this
  # file is processed, so it is named rather than probed with if(TARGET).
  add_executable(fusion_scanner_adapter_test test/cpp/adapter_test.cpp)
  target_link_libraries(fusion_scanner_adapter_test PRIVATE duckdb_static)
  link_extension_libraries(fusion_scanner_adapter_test PRIVATE)
  target_include_directories(fusion_scanner_adapter_test PRIVATE src src/include)
  target_compile_features(fusion_scanner_adapter_test PRIVATE cxx_std_17)
  add_test(NAME fusion_scanner_adapter_test COMMAND fusion_scanner_adapter_test)
endif()

install(
        TARGETS ${EXTENSION_NAME}
        EXPORT "${DUCKDB_EXPORT_SET}"
        LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
        ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")