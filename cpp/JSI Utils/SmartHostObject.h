//
// Created by Szymon on 24/02/2022.
//

#ifndef FASTCRYPTOEXAMPLE_SMARTHOSTOBJECT_H
#define FASTCRYPTOEXAMPLE_SMARTHOSTOBJECT_H

#include "ThreadAwareHostObject.h"
#include "JSIMacros.h"
<<<<<<< HEAD
#include <ReactCommon/TurboModuleUtils.h>
=======
>>>>>>> 774ca1b (feat: add macros)

namespace margelo {

namespace jsi = facebook::jsi;
namespace react = facebook::react;

typedef std::function<jsi::Value (jsi::Runtime & runtime)> JSIValueBuilder;
<<<<<<< HEAD
typedef std::pair<std::string, JSIValueBuilder> FieldDefinition;

class JSI_EXPORT SmartHostObject : public ThreadAwareHostObject {
=======

class SmartHostObject : public ThreadAwareHostObject {
>>>>>>> 774ca1b (feat: add macros)
public:
SmartHostObject(std::shared_ptr<react::CallInvoker> jsCallInvoker,
                std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue)
  : ThreadAwareHostObject(jsCallInvoker, workerQueue) {
}

virtual ~SmartHostObject() {
}

std::vector<jsi::PropNameID> getPropertyNames(jsi::Runtime &runtime);

jsi::Value get(jsi::Runtime &runtime, const jsi::PropNameID &propNameId);

<<<<<<< HEAD
=======
virtual void install(std::vector<std::pair<std::string, JSIValueBuilder> >
                     & fields) {
};
>>>>>>> 774ca1b (feat: add macros)
std::vector<std::pair<std::string, JSIValueBuilder> > fields;
};

}  // namespace margelo

#endif //FASTCRYPTOEXAMPLE_SMARTHOSTOBJECT_H
