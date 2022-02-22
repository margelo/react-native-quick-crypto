#include "JSICryptoHostObject.h"
#include <jsi/jsi.h>

namespace margelo {

using namespace facebook;

// TODO: Create macros for this so we don't have to repeat ourselves for each JSI func?

std::vector<jsi::PropNameID> JSICryptoHostObject::getPropertyNames(jsi::Runtime& runtime) {
    return std::vector<jsi::PropNameID>();
}

jsi::Value JSICryptoHostObject::get(jsi::Runtime& runtime, const jsi::PropNameID& propNameId) {
    auto propName = propNameId.utf8(runtime);

    return jsi::Value::undefined();
}

} // namespace margelo
