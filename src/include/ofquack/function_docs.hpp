#pragma once

#include "duckdb.hpp"

#include <string>
#include <vector>

namespace duckdb {

//! What `duckdb_functions()` shows about a function beyond its signature.
struct FunctionDocs {
	//! One sentence on what the function does.
	std::string description;
	//! One call that runs as written: a bare expression for a scalar function,
	//! a whole `SELECT * FROM f(...)` for a table function, since a table
	//! function used as an expression is a binder error.
	std::string example;
	//! A short tag or two.
	std::vector<std::string> categories;
};

//! Registers a scalar function with its documentation attached.
//! `argument_names` names the positional arguments, in order.
void RegisterDocumented(ExtensionLoader &loader, ScalarFunction function, std::vector<std::string> argument_names,
                        FunctionDocs docs);

//! Registers a table function with its documentation attached.
//! `argument_names` names the positional arguments, in order; the named
//! parameters are named from the function itself.
void RegisterDocumented(ExtensionLoader &loader, TableFunction function, std::vector<std::string> argument_names,
                        FunctionDocs docs);

} // namespace duckdb
