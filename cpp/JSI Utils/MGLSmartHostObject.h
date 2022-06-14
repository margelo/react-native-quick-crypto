//
// Created by Szymon on 24/02/2022.
//

#ifndef MGL_SMARTHOSTOBJECT_H
#define MGL_SMARTHOSTOBJECT_H

#include <ReactCommon/TurboModuleUtils.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "MGLJSIMacros.h"
#include "MGLThreadAwareHostObject.h"

namespace margelo {

namespace jsi = facebook::jsi;
namespace react = facebook::react;

typedef std::function<jsi::Value(jsi::Runtime &runtime)> JSIValueBuilder;

typedef std::pair<std::string, JSIValueBuilder> FieldDefinition;

FieldDefinition buildPair(std::string name, jsi::HostFunctionType &&f);

class JSI_EXPORT MGLSmartHostObject : public MGLThreadAwareHostObject {
 public:
  MGLSmartHostObject(std::shared_ptr<react::CallInvoker> jsCallInvoker,
                     std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue)
      : MGLThreadAwareHostObject(jsCallInvoker, workerQueue) {}

  virtual ~MGLSmartHostObject() {}

  std::vector<jsi::PropNameID> getPropertyNames(jsi::Runtime &runtime);

  jsi::Value get(jsi::Runtime &runtime, const jsi::PropNameID &propNameId);

  std::vector<std::pair<std::string, JSIValueBuilder>> fields;
};

}  // namespace margelo

#endif  // MGL_MGLSMARTHOSTOBJECT_H
