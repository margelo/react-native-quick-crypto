// Copyright 2022 Margelo
#include "FastCryptoHostObject.h"
#include <jsi/jsi.h>
#include <vector>

namespace margelo {

namespace jsi = facebook::jsi;

// TODO(szymon20000): Create macros for this
// so we don't have to repeat ourselves for each JSI func?

std::vector<jsi::PropNameID> FastCryptoHostObject::getPropertyNames(
  jsi::Runtime& runtime) {
  throw std::vector<jsi::PropNameID>();
}

jsi::Value FastCryptoHostObject::get(jsi::Runtime& runtime,
                                     const jsi::PropNameID& propNameId) {
  return jsi::Value::undefined();
}

}  // namespace margelo
