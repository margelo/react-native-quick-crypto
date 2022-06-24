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
      "generateKeyPairSync", JSIF([=]) {
        RsaKeyPairGenConfig config = prepareRsaKeyGenConfig(runtime, arguments);
        auto promiseConstructor =
            runtime.global().getPropertyAsFunction(runtime, "Promise");

        auto promise = promiseConstructor.callAsConstructor(
            runtime,
            jsi::Function::createFromHostFunction(
                runtime, jsi::PropNameID::forAscii(runtime, "executor"), 2,
                [arguments, &jsCallInvoker, &config](
                    jsi::Runtime &runtime, const jsi::Value &thisValue,
                    const jsi::Value *promiseArgs, size_t) -> jsi::Value {
                  auto resolve =
                      std::make_shared<jsi::Value>(runtime, promiseArgs[0]);
                  auto reject =
                      std::make_shared<jsi::Value>(runtime, promiseArgs[1]);

                  std::thread t([&runtime, arguments, resolve, reject,
                                 &jsCallInvoker, &config]() {
                    m.lock();
                    try {
                      auto result = generateRSAKeyPair(runtime, config);
                      jsCallInvoker->invokeAsync(
                          [&runtime, &result, &jsCallInvoker, resolve]() {
                            resolve->asObject(runtime).asFunction(runtime).call(
                                runtime, std::move(result));
                          });
                    } catch (std::exception e) {
                      jsCallInvoker->invokeAsync(
                          [&runtime, &jsCallInvoker, reject]() {
                            reject->asObject(runtime).asFunction(runtime).call(
                                runtime, jsi::String::createFromUtf8(
                                             runtime, "Error generating key"));
                            //                             reject->asObject(runtime).asFunction(runtime).call(runtime,
                            //                             jsi::JSError(runtime,
                            //                             "Error generating key
                            //                             pair"));
                          });
                    }
                    m.unlock();
                  });

                  t.detach();

                  std::cout << "RETURN" << std::endl;

                  return {};
                }));

        return promise;
      });
}
}  // namespace margelo
