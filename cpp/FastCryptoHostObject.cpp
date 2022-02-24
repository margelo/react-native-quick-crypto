// Copyright 2022 Margelo
#include "FastCryptoHostObject.h"
#include <jsi/jsi.h>
#include <vector>
#include <ReactCommon/TurboModuleUtils.h>

namespace margelo {

namespace jsi = facebook::jsi;

// TODO(szymon20000): Create macros for this
// so we don't have to repeat ourselves for each JSI func?

FastCryptoHostObject::FastCryptoHostObject(std::shared_ptr<react::CallInvoker> jsCallInvoker, std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue) :
  SmartHostObject(jsCallInvoker, workerQueue) {
  install(this->fields);
}

void FastCryptoHostObject::install(std::vector<std::pair<std::string, JSIValueBuilder> > & fields) {
  /*fields.push_back(HOST_LAMBDA("runAsync", {
       return react::createPromiseAsJSIValue(runtime, [this](jsi::Runtime &runtime,
       std::shared_ptr<react::Promise> promise) {
           this->runOnWorkerThread([this, promise]() {
               this->runOnJSThread([=]() {
                   promise->resolve(5);
               });
           });
       });
     }));*/
  /* fields.push_back(JSI_VALUE("x", {
       return jsi::Value(runtime, 5);
     }));*/
}

}  // namespace margelo
