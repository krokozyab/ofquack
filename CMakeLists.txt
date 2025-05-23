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
include_directories(src/include)

set(EXTENSION_SOURCES src/ofquack_extension.cpp
        src/base64.cpp
)

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

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