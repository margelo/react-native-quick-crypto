// Copyright 2022 Margelo
#include "FastCryptoHostObject.h"
#include <ReactCommon/TurboModuleUtils.h>
#include <jsi/jsi.h>
#include <vector>
#include <memory>
#include "HMAC/HmacInstaller.h"
#include "fastpbkdf2/Pbkdf2HostObject.h"

namespace margelo {

namespace jsi = facebook::jsi;

FastCryptoHostObject::FastCryptoHostObject(std::shared_ptr<react::CallInvoker> jsCallInvoker,
                                           std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue) :
  SmartHostObject(jsCallInvoker, workerQueue) {
  this->fields.push_back(HOST_LAMBDA("runAsync", {
      return react::createPromiseAsJSIValue(runtime, [this](jsi::Runtime &runtime,
                                                            std::shared_ptr<react::Promise> promise) {
	this->runOnWorkerThread([this, promise]() {
	  this->runOnJSThread([=]() {
	    promise->resolve(5);
	  });
	});
      });
    }));
  this->fields.push_back(getHmacFieldDefinition(jsCallInvoker, workerQueue));
  this->fields.push_back(JSI_VALUE("pbkdf2", {
      auto hostObject = std::make_shared<Pbkdf2HostObject>(jsCallInvoker,
                                                           workerQueue);
      return jsi::Object::createFromHostObject(runtime, hostObject);
    }));
}

}  // namespace margelo
