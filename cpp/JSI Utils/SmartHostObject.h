//
// Created by Szymon on 24/02/2022.
//

#ifndef FASTCRYPTOEXAMPLE_SMARTHOSTOBJECT_H
#define FASTCRYPTOEXAMPLE_SMARTHOSTOBJECT_H

#include <ReactCommon/TurboModuleUtils.h>

#include "JSIMacros.h"
#include "ThreadAwareHostObject.h"

namespace margelo {

namespace jsi = facebook::jsi;
namespace react = facebook::react;

typedef std::function<jsi::Value (jsi::Runtime &runtime)> JSIValueBuilder;

typedef std::pair<std::string, JSIValueBuilder> FieldDefinition;

FieldDefinition buildPair(std::string name, jsi::HostFunctionType &&f);

class JSI_EXPORT SmartHostObject : public ThreadAwareHostObject {
public:
SmartHostObject(std::shared_ptr<react::CallInvoker> jsCallInvoker,
                std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue)
  : ThreadAwareHostObject(jsCallInvoker, workerQueue) {
}

virtual ~SmartHostObject() {
}

std::vector<jsi::PropNameID> getPropertyNames(jsi::Runtime &runtime);

jsi::Value get(jsi::Runtime &runtime, const jsi::PropNameID &propNameId);

std::vector<std::pair<std::string, JSIValueBuilder> > fields;
};

}  // namespace margelo

#endif  // FASTCRYPTOEXAMPLE_SMARTHOSTOBJECT_H
