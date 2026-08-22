// The macros <windows.h> defines that collide with ordinary C++ identifiers.
//
// This is not a Windows header and defines nothing Windows-specific. It exists
// so a Linux or macOS compiler can be made to reproduce the one class of
// Windows breakage that is pure preprocessor: `min`, `max`, `IN` and `OUT` are
// macros there, and an `enum class` is no protection against the preprocessor.
//
// Force-included by scripts/build_protocol_test.sh in its second pass, so this
// is caught by a real compiler in seconds rather than by a Windows runner forty
// minutes later. Every one of these bit this project once.

#pragma once

// minwindef.h, verbatim in spirit.
#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))

// The SAL-ish annotations from winnt.h, which expand to nothing and therefore
// silently delete any enumerator or parameter that happens to be named after
// them.
#define IN
#define OUT

// A few more that windows.h defines and that read like ordinary names.
#define NEAR
#define FAR
#define OPTIONAL
