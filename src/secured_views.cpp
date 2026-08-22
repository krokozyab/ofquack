#include "ofquack/secured_views.hpp"

#include "ofquack/sql_text.hpp"

#include <cctype>

namespace ofquack {

const std::vector<std::pair<std::string, std::string>> &SecuredViewMappings() {
	// HR_ALL_ORGANIZATION_UNITS_F maps to PER_LEGAL_EMPL_SECURED_LIST_V, not to
	// PER_DEPARTMENT_SECURED_LIST_V: the JDBC driver lists both and its map
	// keeps the last, so the department mapping has never been in effect.
	static const std::vector<std::pair<std::string, std::string>> MAPPINGS = {
	    {"HR_ALL_ORGANIZATION_UNITS_F", "PER_LEGAL_EMPL_SECURED_LIST_V"},
	    {"HR_ALL_POSITIONS_F", "PER_POSITION_SECURED_LIST_V"},
	    {"PER_JOBS_F", "PER_JOB_SECURED_LIST_V"},
	    {"PER_LOCATIONS", "PER_LOCATION_SECURED_LIST_V"},
	    {"PER_GRADES_F", "PER_GRADE_SECURED_LIST_V"},
	    {"PER_ALL_PEOPLE_F", "PER_PERSON_SECURED_LIST_V"},
	    {"PER_PERSONS", "PER_PUB_PERS_SECURED_LIST_V"},
	    {"PER_LEGISLATIVE_DATA_GROUPS", "PER_LDG_SECURED_LIST_V"},
	    {"PAY_ALL_PAYROLLS_F", "PAY_PAYROLL_SECURED_LIST_V"},
	    {"CMP_SALARY", "CMP_SALARY_SECURED_LIST_V"},
	    {"PER_ALL_ASSIGNMENTS_M", "PER_ASSIGNMENT_SECURED_LIST_V"},
	};
	return MAPPINGS;
}

std::string ApplySecuredViews(const std::string &sql) {
	auto rewritten = sql;
	for (const auto &mapping : SecuredViewMappings()) {
		// Rewritten one occurrence at a time, always searching past what has
		// already been replaced: the replacement text contains the search text
		// for none of these pairs, but restarting the scan is what keeps that
		// true if the table ever gains a name that overlaps its view.
		size_t from = 0;
		for (;;) {
			const auto found = FindKeyword(rewritten.substr(from), mapping.first);
			if (found == std::string::npos) {
				break;
			}
			const auto at = from + found;
			rewritten.replace(at, mapping.first.size(), mapping.second);
			from = at + mapping.second.size();
		}
	}
	return rewritten;
}

} // namespace ofquack
