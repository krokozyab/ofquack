#include "ofquack/transport.hpp"

#include "ofquack/soap_transport.hpp"

namespace ofquack {

const RequestContext &RequestContext::None() {
	static const RequestContext none;
	return none;
}

namespace {

//! Null means "no override installed": fall through to the real transport.
TransportFactory &ActiveFactory() {
	static TransportFactory factory;
	return factory;
}

} // namespace

std::shared_ptr<FusionTransport> CreateTransport(const FusionConfig &config) {
	auto &factory = ActiveFactory();
	if (factory) {
		return factory(config);
	}
	return CreateSoapTransport(config);
}

ScopedTransportFactory::ScopedTransportFactory(TransportFactory factory) : previous(ActiveFactory()) {
	ActiveFactory() = std::move(factory);
}

ScopedTransportFactory::~ScopedTransportFactory() {
	ActiveFactory() = std::move(previous);
}

} // namespace ofquack
