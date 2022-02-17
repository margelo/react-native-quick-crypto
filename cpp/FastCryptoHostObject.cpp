#include "FastCryptoHostObject.h"
#include <jsi/jsi.h>

namespace margelo {

using namespace facebook;

// TODO: Create macros for this so we don't have to repeat ourselves for each JSI func?

std::vector<jsi::PropNameID> FastCryptoHostObject::getPropertyNames(jsi::Runtime& runtime) {
	throw std::runtime_error("Not yet implemented!");
}

jsi::Value FastCryptoHostObject::get(jsi::Runtime& runtime, const jsi::PropNameID& propNameId) {
  auto propName = propNameId.utf8(runtime);

	throw std::runtime_error("Not yet implemented!");
}

} // namespace margelo
