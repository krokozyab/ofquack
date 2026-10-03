#include "ofquack/function_docs.hpp"

#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/parser/parsed_data/create_scalar_function_info.hpp"
#include "duckdb/parser/parsed_data/create_table_function_info.hpp"

namespace duckdb {

namespace {

//! Names the positional arguments in the function's own signature.
//!
//! DuckDB 2.0 reports a parameter's name from the signature rather than from
//! the description, so a positional argument left unnamed shows as `col<n>`
//! whatever the description says. Only positional-only parameters are renamed,
//! which keeps them positional-only: no call gains a keyword form it did not
//! have. The named options need nothing here -- they are listed under the names
//! they were declared with, in the order they were declared.
template <class FUNCTION>
void NameArguments(FUNCTION &function, const std::vector<std::string> &argument_names) {
	auto &signature = function.GetSignature();
	D_ASSERT(argument_names.size() == signature.GetPositionalOnlyParameterCount());
	for (idx_t index = 0; index < argument_names.size() && index < signature.GetParameterCount(); index++) {
		auto &parameter = signature.GetParameter(index);
		if (parameter.GetKind() == FunctionParameterKind::POSITIONAL_ONLY) {
			parameter.SetName(Identifier(argument_names[index]));
		}
	}
}

FunctionDescription Describe(std::vector<std::string> argument_names, FunctionDocs docs) {
	FunctionDescription description;
	description.parameter_names = std::move(argument_names);
	description.description = std::move(docs.description);
	description.examples = {std::move(docs.example)};
	description.categories = std::move(docs.categories);
	return description;
}

} // namespace

void RegisterDocumented(ExtensionLoader &loader, ScalarFunction function, std::vector<std::string> argument_names,
                        FunctionDocs docs) {
	NameArguments(function, argument_names);
	CreateScalarFunctionInfo info(std::move(function));
	// What the bare RegisterFunction overload sets; a CreateInfo defaults to
	// ERROR_ON_CONFLICT.
	info.on_conflict = OnCreateConflict::ALTER_ON_CONFLICT;
	info.descriptions.push_back(Describe(std::move(argument_names), std::move(docs)));
	loader.RegisterFunction(std::move(info));
}

void RegisterDocumented(ExtensionLoader &loader, TableFunction function, std::vector<std::string> argument_names,
                        FunctionDocs docs) {
	NameArguments(function, argument_names);
	CreateTableFunctionInfo info(std::move(function));
	info.on_conflict = OnCreateConflict::ALTER_ON_CONFLICT;
	info.descriptions.push_back(Describe(std::move(argument_names), std::move(docs)));
	loader.RegisterFunction(std::move(info));
}

} // namespace duckdb
