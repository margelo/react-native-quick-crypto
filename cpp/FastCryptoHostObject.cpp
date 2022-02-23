// Copyright 2022 Margelo
#include "FastCryptoHostObject.h"
#include <jsi/jsi.h>
#include <vector>
#include <ReactCommon/TurboModuleUtils.h>

namespace margelo {

namespace jsi = facebook::jsi;

// TODO(szymon20000): Create macros for this
// so we don't have to repeat ourselves for each JSI func?

void FastCryptoHostObject::runOnWorkerThread(std::function<void()> &&job) {
  this->dispatchQueue.dispatch(std::move(job));
}

void FastCryptoHostObject::runOnJSThread(std::function<void()> &&job) {
  auto callInvoker = this->weakJsCallInvoker.lock();
  if (callInvoker != nullptr) {
    this->dispatchQueue.dispatch(std::move(job));
  }
}

std::vector<jsi::PropNameID> FastCryptoHostObject::getPropertyNames(
  jsi::Runtime& runtime) {
  std::vector<jsi::PropNameID> propertyNames;
  propertyNames.push_back(jsi::PropNameID::forAscii(runtime, "runAsync"));
  return propertyNames;
}

jsi::Value FastCryptoHostObject::get(jsi::Runtime& runtime,
                                     const jsi::PropNameID& propNameId) {
  auto name = propNameId.utf8(runtime);
  if (name == "runAsync") {
    auto runAsync = [&](jsi::Runtime &runtime, const jsi::Value &thisValue,
                        const jsi::Value *arguments, size_t count) -> jsi::Value {

		      return react::createPromiseAsJSIValue(runtime, [this](jsi::Runtime &runtime,
		                                                            std::shared_ptr<react::Promise> promise) {
	  this->runOnWorkerThread([this, promise]() {
	    this->runOnJSThread([=]() {
	      promise->resolve(5);
	    });
	  });
	});
		    };
    return jsi::Function::createFromHostFunction(runtime, propNameId, 0, runAsync);
  }
  return jsi::Value::undefined();
}

}  // namespace margelo
