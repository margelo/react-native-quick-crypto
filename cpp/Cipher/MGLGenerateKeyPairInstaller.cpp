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
#include "JSIUtils/MGLTypedArray.h"
#else
#include "MGLJSIMacros.h"
#include "MGLTypedArray.h"
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
                      const auto keys = generateRSAKeyPair(runtime, config);
                      jsCallInvoker->invokeAsync([&runtime, keys, jsCallInvoker,
                                                  resolve]() {
                        if (keys.first.isString && keys.second.isString) {
                          auto publicKey = jsi::String::createFromUtf8(
                              runtime, keys.first.stringValue);
                          auto privateKey = jsi::String::createFromUtf8(
                              runtime, keys.second.stringValue);
                          auto res = jsi::Array::createWithElements(
                              runtime, jsi::Value::undefined(), publicKey,
                              privateKey);
                          resolve->asObject(runtime).asFunction(runtime).call(
                              runtime, std::move(res));
                        } else {
                          MGLTypedArray<MGLTypedArrayKind::Uint8Array>
                              publicKeyBuffer(runtime, keys.first.vectorValue);
                          MGLTypedArray<MGLTypedArrayKind::Uint8Array>
                              privateKeyBuffer(runtime,
                                               keys.second.vectorValue);

                          auto res = jsi::Array::createWithElements(
                              runtime, jsi::Value::undefined(), publicKeyBuffer,
                              privateKeyBuffer);
                          resolve->asObject(runtime).asFunction(runtime).call(
                              runtime, std::move(res));
                        }
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
