cmake_minimum_required(VERSION 3.5)

# Set extension name here
set(TARGET_NAME ofquack)

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

set(EXTENSION_SOURCES src/ofquack_extension.cpp
        src/base64.cpp
)

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

install(
        TARGETS ${EXTENSION_NAME}
        EXPORT "${DUCKDB_EXPORT_SET}"
        LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
        ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")