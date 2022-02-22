// "Copyright 2022 Margelo
#include "JSICryptoHostObject.h"

#include <jsi/jsi.h>
#include <vector>

namespace margelo {

namespace jsi = facebook::jsi;

// TODO(Szymon): Create macros for this
// so we don't have to repeat ourselves for each
// JSI func?

std::vector<jsi::PropNameID> JSICryptoHostObject::getPropertyNames(
  jsi::Runtime& runtime) {
  return std::vector<jsi::PropNameID>();
}

jsi::Value JSICryptoHostObject::get(jsi::Runtime& runtime,
                                    const jsi::PropNameID& propNameId) {
  // auto propName = propNameId.utf8(runtime);

  return jsi::Value::undefined();
}

}  // namespace margelo
