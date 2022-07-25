#include "MGLVerifyInstaller.h"

#include "MGLSignHostObjects.h"
#ifdef ANDROID
#include "JSIUtils/MGLJSIMacros.h"
#else
#include "MGLJSIMacros.h"
#include "logs.h"
#endif

namespace margelo {

FieldDefinition getVerifyFieldDefinition(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue) {
  return buildPair(
      "createVerify", JSIF([=]) {
        auto hostObject =
            std::make_shared<MGLVerifyHostObject>(jsCallInvoker, workerQueue);
        return jsi::Object::createFromHostObject(runtime, hostObject);
      });
}

}  // namespace margelo
