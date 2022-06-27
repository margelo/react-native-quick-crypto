//
//  MGLGenerateKeyPairInstaller.cpp
//  react-native-quick-crypto
//
//  Created by Oscar on 24.06.22.
//

#include "MGLGenerateKeyPairInstaller.h"

#include <iostream>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>

#include "MGLRsa.h"

#ifdef ANDROID
#include "JSIUtils/MGLJSIMacros.h"
#else
#include "MGLJSIMacros.h"
#endif

using namespace facebook;

namespace margelo {

std::mutex m;

// Current implementation only supports RSA schemes (check line config.variant =
// ) As more encryption schemes are added this will require an abstraction that
// supports more schemes
FieldDefinition getGenerateKeyPairFieldDefinition(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue) {
  return buildPair(
      "generateKeyPair", JSIF([=]) {
        auto config = std::make_shared<RsaKeyPairGenConfig>(
            prepareRsaKeyGenConfig(runtime, arguments));
        auto promiseConstructor =
            runtime.global().getPropertyAsFunction(runtime, "Promise");

        auto promise = promiseConstructor.callAsConstructor(
            runtime,
            jsi::Function::createFromHostFunction(
                runtime, jsi::PropNameID::forAscii(runtime, "executor"), 2,
                [arguments, &jsCallInvoker, config](
                    jsi::Runtime &runtime, const jsi::Value &,
                    const jsi::Value *promiseArgs, size_t) -> jsi::Value {
                  auto resolve =
                      std::make_shared<jsi::Value>(runtime, promiseArgs[0]);
                  auto reject =
                      std::make_shared<jsi::Value>(runtime, promiseArgs[1]);

                  std::thread t([&runtime, arguments, resolve, reject,
                                 jsCallInvoker, config]() {
                    m.lock();
                    try {
                      // Here be a lot of concurrency moving
                      // First take the object created by generate key pair and
                      // turn it into an object to allow copy semantics.
                      const auto result = generateRSAKeyPair(runtime, config)
                                              .getObject(runtime);
                      // Allocate a copy in the heap to prevent stack
                      // de-allocation
                      const auto *tempResult = new jsi::Value(runtime, result);
                      jsCallInvoker->invokeAsync([&runtime, tempResult,
                                                  jsCallInvoker, resolve]() {
                        // Create a copy in this inner function stack
                        // this will be really returned to the JS context
                        const auto tempResult2 =
                            jsi::Value(runtime, tempResult->getObject(runtime));
                        resolve->asObject(runtime).asFunction(runtime).call(
                            runtime, std::move(tempResult2));
                        // Delete the heap copy we had
                        delete tempResult;
                      });
                    } catch (std::exception e) {
                      jsCallInvoker->invokeAsync(
                          [&runtime, &jsCallInvoker, reject]() {
                            reject->asObject(runtime).asFunction(runtime).call(
                                runtime, jsi::String::createFromUtf8(
                                             runtime, "Error generating key"));
                          });
                    }
                    m.unlock();
                  });

                  t.detach();

                  return {};
                }));

        return promise;
      });
}
}  // namespace margelo
