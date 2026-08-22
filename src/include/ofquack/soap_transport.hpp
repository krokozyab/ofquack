#pragma once

#include "ofquack/transport.hpp"

namespace ofquack {

//! The real transport: builds the SOAP envelope, POSTs it to BI Publisher with
//! Basic auth, and hands back the response body.
std::shared_ptr<FusionTransport> CreateSoapTransport(const FusionConfig &config);

} // namespace ofquack
