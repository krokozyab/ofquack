#pragma once

#include <string>
#include <utility>
#include <vector>

namespace ofquack {

//! HR tables whose rows are restricted, paired with the view that applies the
//! restriction.
//!
//! Querying the base table returns rows the caller may not be entitled to see;
//! the *_SECURED_LIST_V views apply Fusion's row-level security. The JDBC
//! driver's list has twelve entries but only eleven mappings, because
//! HR_ALL_ORGANIZATION_UNITS_F appears twice and the later entry wins. That
//! resolution is reproduced here explicitly rather than left to map ordering,
//! which C++ does not guarantee.
const std::vector<std::pair<std::string, std::string>> &SecuredViewMappings();

//! Replaces every secured table name in `sql` with its view.
//!
//! Whole-word and case-insensitive. Names inside string literals and quoted
//! identifiers are left alone: a table name is not the same thing as a value
//! that happens to spell one.
std::string ApplySecuredViews(const std::string &sql);

} // namespace ofquack
