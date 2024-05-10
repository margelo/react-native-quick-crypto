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
#include <string>
#include <thread>
#include <utility>

#include "MGLRsa.h"

#ifdef ANDROID
#include "JSIUtils/MGLJSIMacros.h"
#include "JSIUtils/MGLTypedArray.h"
#include "webcrypto/crypto_ec.h"
#else
#include "MGLJSIMacros.h"
#include "MGLTypedArray.h"
#include "crypto_ec.h"
#endif

using namespace facebook;

namespace margelo {

std::mutex m;

FieldDefinition getGenerateKeyPairFieldDefinition(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue) {
  return buildPair(
      "generateKeyPair", JSIF([=]) {

        KeyVariant variant =
          static_cast<KeyVariant>((int)arguments[0].asNumber());
        std::shared_ptr<RsaKeyPairGenConfig> rsaConfig;
        std::shared_ptr<EcKeyPairGenConfig> ecConfig;

        // switch on variant to get proper config from arguments
        // outside of lambda 🤮
        if (variant == kvRSA_SSA_PKCS1_v1_5 ||
            variant == kvRSA_PSS ||
            variant == kvRSA_OAEP
        ) {
          rsaConfig = std::make_shared<RsaKeyPairGenConfig>(
            prepareRsaKeyGenConfig(runtime, arguments));
        } else
        if (variant == kvEC) {
          ecConfig = std::make_shared<EcKeyPairGenConfig>(
            prepareEcKeyGenConfig(runtime, arguments));
        } else {
          throw std::runtime_error("KeyVariant not implemented"
            + std::to_string((int)variant));
        }

        auto promiseConstructor =
            runtime.global().getPropertyAsFunction(runtime, "Promise");

        auto promise = promiseConstructor.callAsConstructor(
            runtime,
            jsi::Function::createFromHostFunction(
                runtime,
                jsi::PropNameID::forAscii(runtime, "executor"),
                4,
                [&jsCallInvoker, variant, rsaConfig, ecConfig](
                    jsi::Runtime &runtime, const jsi::Value &,
                    const jsi::Value *promiseArgs, size_t) -> jsi::Value {
                  auto resolve =
                      std::make_shared<jsi::Value>(runtime, promiseArgs[0]);
                  auto reject =
                      std::make_shared<jsi::Value>(runtime, promiseArgs[1]);

                  std::thread t([&runtime, resolve, reject, jsCallInvoker,
                      variant, rsaConfig, ecConfig]() {
                    m.lock();
                    try {
                      jsCallInvoker->invokeAsync([&runtime, resolve,
                          variant, rsaConfig, ecConfig]() {
                        std::pair<JSVariant, JSVariant> keys;

                        // switch on variant to get proper generateKeyPair
                        if (variant == kvRSA_SSA_PKCS1_v1_5 ||
                            variant == kvRSA_PSS ||
                            variant == kvRSA_OAEP
                        ) {
                          keys = generateRsaKeyPair(runtime, rsaConfig);
                        } else
                        if (variant == kvEC) {
                          keys = generateEcKeyPair(runtime, ecConfig);
                        } else {
                          throw std::runtime_error("KeyVariant not implemented"
                            + std::to_string((int)variant));
                        }

                        auto publicKey = toJSI(runtime, keys.first);
                        auto privateKey = toJSI(runtime, keys.second);
                        auto res = jsi::Array::createWithElements(
                          runtime,
                          jsi::Value::undefined(),
                          publicKey,
                          privateKey);
                        resolve->asObject(runtime).asFunction(runtime).call(
                            runtime, std::move(res));
                      });
                    } catch (std::exception e) {
                      jsCallInvoker->invokeAsync(
                          [&runtime, reject]() {
                            auto res = jsi::Array::createWithElements(
                              runtime,
                              jsi::String::createFromUtf8(
                                runtime, "Error generating key"),
                              jsi::Value::undefined(),
                              jsi::Value::undefined());
                            reject->asObject(runtime).asFunction(runtime).call(
                                runtime, std::move(res));
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
