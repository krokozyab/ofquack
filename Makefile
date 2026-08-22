PROJ_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Configuration of extension
EXT_NAME=ofquack
EXT_CONFIG=${PROJ_DIR}extension_config.cmake

# Include the Makefile from extension-ci-tools
include extension-ci-tools/makefiles/duckdb_extension.Makefile

# The reusable makefile is consumed as a quoted shell fragment in some
# environments. Normalize path variables here so its test recipes resolve the
# actual debug/release unittest binary rather than a path containing quotes.
TEST_PATH := /test/unittest
TESTS_BASE_DIRECTORY := test/