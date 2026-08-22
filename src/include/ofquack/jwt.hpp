#pragma once

#include <cstdint>
#include <string>

namespace ofquack {

struct JwtClaims {
	bool parsed = false;
	//! Expiry as seconds since the epoch. Zero when the token carried none.
	int64_t expires_at_epoch = 0;
	//! The subject, used only to tell the user who they are signed in as.
	std::string subject;
};

//! Reads the claims out of a JWT without verifying anything.
//!
//! The signature is deliberately **not** checked. This is not authentication --
//! Fusion does that when the token is used. It is a way to know when to ask for
//! a new one, so the only thing wanted is the expiry, and a token this code
//! received from the browser it launched is not a token it needs to police.
JwtClaims ParseJwtClaims(const std::string &token);

//! Decodes base64url, which JWT uses: '-' and '_' for '+' and '/', and padding
//! left off.
std::string DecodeBase64Url(const std::string &encoded);

} // namespace ofquack
