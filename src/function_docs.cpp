#include "ofquack/function_docs.hpp"

#include "duckdb/catalog/catalog.hpp"
#include "duckdb/catalog/catalog_entry/schema_catalog_entry.hpp"
#include "duckdb/catalog/catalog_entry/table_function_catalog_entry.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/parser/parsed_data/create_scalar_function_info.hpp"
#include "duckdb/parser/parsed_data/create_table_function_info.hpp"

namespace duckdb {

namespace {

FunctionDescription Describe(std::vector<std::string> argument_names, FunctionDocs docs) {
	FunctionDescription description;
	description.parameter_names = std::move(argument_names);
	description.description = std::move(docs.description);
	description.examples = {std::move(docs.example)};
	description.categories = std::move(docs.categories);
	return description;
}

//! Appends the named parameters to the registered description.
//!
//! duckdb_functions() lists a table function's positional arguments and then
//! its named parameters, and takes each name from the description by position;
//! a position the description does not cover is shown as `col<n>`. The named
//! part comes in whatever order the stored parameter map iterates, and that is
//! not knowable before registration: libc++ reverses an unordered_map's order
//! on every copy while libstdc++ and MSVC keep it, and CreateTableFunctionInfo
//! is copied on its way into the catalog. So the order is read back from the
//! entry, the same way duckdb_functions() reads it.
void NameNamedParameters(ExtensionLoader &loader, const std::string &name) {
	auto &db = loader.GetDatabaseInstance();
	auto transaction = CatalogTransaction::GetSystemTransaction(db);
	auto &schema = Catalog::GetSystemCatalog(db).GetSchema(transaction, DEFAULT_SCHEMA);
	auto entry = schema.GetEntry(transaction, CatalogType::TABLE_FUNCTION_ENTRY, name);
	D_ASSERT(entry);
	if (!entry) {
		return;
	}
	auto &function = entry->Cast<TableFunctionCatalogEntry>();
	D_ASSERT(function.functions.Size() == 1);
	const auto shown = function.functions.GetFunctionByOffset(0);
	for (auto &description : function.descriptions) {
		// Rebuilt rather than appended to, so a second registration of the same
		// name cannot list a parameter twice.
		description.parameter_names.resize(shown.arguments.size());
		for (const auto &parameter : shown.named_parameters) {
			description.parameter_names.push_back(parameter.first);
		}
	}
}

} // namespace

void RegisterDocumented(ExtensionLoader &loader, ScalarFunction function, std::vector<std::string> argument_names,
                        FunctionDocs docs) {
	D_ASSERT(argument_names.size() == function.arguments.size());
	CreateScalarFunctionInfo info(std::move(function));
	// What the bare RegisterFunction overload sets; a CreateInfo defaults to
	// ERROR_ON_CONFLICT.
	info.on_conflict = OnCreateConflict::ALTER_ON_CONFLICT;
	info.descriptions.push_back(Describe(std::move(argument_names), std::move(docs)));
	loader.RegisterFunction(std::move(info));
}

void RegisterDocumented(ExtensionLoader &loader, TableFunction function, std::vector<std::string> argument_names,
                        FunctionDocs docs) {
	D_ASSERT(argument_names.size() == function.arguments.size());
	const auto name = function.name;
	CreateTableFunctionInfo info(std::move(function));
	info.on_conflict = OnCreateConflict::ALTER_ON_CONFLICT;
	info.descriptions.push_back(Describe(std::move(argument_names), std::move(docs)));
	loader.RegisterFunction(std::move(info));
	NameNamedParameters(loader, name);
}

} // namespace duckdb
