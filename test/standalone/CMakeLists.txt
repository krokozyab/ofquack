# Builds the pure unit suite on its own, without DuckDB.
#
# The main CMakeLists.txt is included by DuckDB's build system and depends on
# it (build_static_extension, link_extension_libraries, the duckdb_static
# target), so it cannot be configured standalone. That is fine for the extension
# itself, but it means the fast tests would otherwise cost a full DuckDB build
# to run -- which defeats the point of having them.
#
# Everything listed here belongs to the layers that know neither DuckDB nor the
# query engine. If a file stops building here, it has grown a dependency on
# DuckDB and belongs on the other side of the seam.

cmake_minimum_required(VERSION 3.16)
project(ofquack_pure_tests CXX)

set(OFQUACK_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
find_package(tinyxml2 QUIET)

add_executable(ofquack_pure_test
        ${OFQUACK_ROOT}/test/cpp/pure_test.cpp
        ${OFQUACK_ROOT}/src/soap_envelope.cpp
        ${OFQUACK_ROOT}/src/xml_report.cpp
        ${OFQUACK_ROOT}/src/error_decoder.cpp
        ${OFQUACK_ROOT}/src/sql_text.cpp
        ${OFQUACK_ROOT}/src/sql_rewrite.cpp
        ${OFQUACK_ROOT}/src/type_inference.cpp
        ${OFQUACK_ROOT}/src/oracle_type_map.cpp
        ${OFQUACK_ROOT}/src/secured_views.cpp
        ${OFQUACK_ROOT}/src/metadata_queries.cpp
        ${OFQUACK_ROOT}/src/retry.cpp
        ${OFQUACK_ROOT}/src/circuit_breaker.cpp
        ${OFQUACK_ROOT}/src/host_throttle.cpp
        ${OFQUACK_ROOT}/src/jwt.cpp
        ${OFQUACK_ROOT}/src/token_cache.cpp
        ${OFQUACK_ROOT}/src/json_util.cpp
        ${OFQUACK_ROOT}/src/websocket.cpp
        ${OFQUACK_ROOT}/src/browser_auth.cpp
        ${OFQUACK_ROOT}/src/proc.cpp
        ${OFQUACK_ROOT}/src/http_curl.cpp
        ${OFQUACK_ROOT}/src/base64.cpp)

target_include_directories(ofquack_pure_test PRIVATE ${OFQUACK_ROOT}/src ${OFQUACK_ROOT}/src/include)
target_compile_features(ofquack_pure_test PRIVATE cxx_std_17)
target_link_libraries(ofquack_pure_test PRIVATE OpenSSL::SSL OpenSSL::Crypto CURL::libcurl)

if(tinyxml2_FOUND)
  target_link_libraries(ofquack_pure_test PRIVATE tinyxml2::tinyxml2)
else()
  # Distribution packages do not all ship a CMake config for tinyxml2.
  target_link_libraries(ofquack_pure_test PRIVATE tinyxml2)
endif()

enable_testing()
add_test(NAME ofquack_pure_test COMMAND ofquack_pure_test)
