//
// Created by Szymon on 24/02/2022.
//

#ifndef FASTCRYPTOEXAMPLE_SMARTHOSTOBJECT_H
#define FASTCRYPTOEXAMPLE_SMARTHOSTOBJECT_H

#include "ThreadAwareHostObject.h"
#include "JSIMacros.h"
#include <ReactCommon/TurboModuleUtils.h>

namespace margelo {

namespace jsi = facebook::jsi;
namespace react = facebook::react;

typedef std::function<jsi::Value (jsi::Runtime & runtime)> JSIValueBuilder;
<<<<<<< HEAD
typedef std::pair<std::string, JSIValueBuilder> FieldDefinition;

class JSI_EXPORT SmartHostObject : public ThreadAwareHostObject {
=======

<<<<<<< HEAD
class SmartHostObject : public ThreadAwareHostObject {
>>>>>>> 774ca1b (feat: add macros)
=======
class JSI_EXPORT SmartHostObject : public ThreadAwareHostObject {
>>>>>>> 30d4e2f (minor fixes)
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
<<<<<<< HEAD
=======
virtual void install(std::vector<std::pair<std::string, JSIValueBuilder> >
                     & fields) {
};
>>>>>>> 774ca1b (feat: add macros)
=======
>>>>>>> 30d4e2f (minor fixes)
std::vector<std::pair<std::string, JSIValueBuilder> > fields;
};

}  // namespace margelo

#endif //FASTCRYPTOEXAMPLE_SMARTHOSTOBJECT_H
