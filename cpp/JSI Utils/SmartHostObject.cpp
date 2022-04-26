//
// Created by Szymon on 24/02/2022.
//

#include "SmartHostObject.h"

namespace margelo {

namespace jsi = facebook::jsi;
namespace react = facebook::react;

FieldDefinition buildPair(std::string name, jsi::HostFunctionType &&f) {
  auto valueBuilder = [f, name](jsi::Runtime &runtime) {
    const auto func = f;
    auto propNameID = jsi::PropNameID::forAscii(runtime, name);
    return jsi::Function::createFromHostFunction(runtime, propNameID, 0, func);
  };
  return std::make_pair(name, valueBuilder);
}

std::vector<jsi::PropNameID> SmartHostObject::getPropertyNames(
    jsi::Runtime &runtime) {
  std::vector<jsi::PropNameID> propertyNames;
  for (auto field : fields) {
    propertyNames.push_back(jsi::PropNameID::forAscii(runtime, field.first));
  }
  return propertyNames;
}

// TODO(Szymon) maybe add memoization here
jsi::Value SmartHostObject::get(jsi::Runtime &runtime,
                                const jsi::PropNameID &propNameId) {
  auto name = propNameId.utf8(runtime);
  for (auto field : fields) {
    auto fieldName = field.first;
    if (fieldName == name) {
      return (field.second)(runtime);
    }
  }
  return jsi::Value::undefined();
}

}  // namespace margelo