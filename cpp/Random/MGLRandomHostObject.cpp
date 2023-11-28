//
// Created by Szymon on 25/02/2022.
//

#include "MGLRandomHostObject.h"

#ifdef ANDROID
#include "JSIUtils/MGLTypedArray.h"
#else
#include "MGLTypedArray.h"
#endif
#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>

#include <memory>
#include <utility>

namespace margelo {
namespace jsi = facebook::jsi;
namespace react = facebook::react;

MGLRandomHostObject::MGLRandomHostObject(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue)
    : MGLSmartHostObject(jsCallInvoker, workerQueue) {
  this->fields.push_back(buildPair(
      "randomFill", JSIF([=]) {
        if (count != 3) {
          throw jsi::JSError(runtime,
                             "randomFill(..) expects exactly 4 arguments!");
        }
          
      if(!arguments[0].isObject() || !arguments[0].asObject(runtime).isArrayBuffer(runtime)) {
          throw std::runtime_error("First argument it not an array buffer");
      }

        auto result = arguments[0].asObject(runtime).getArrayBuffer(runtime);
        auto resultSize = result.size(runtime);
        auto *resultData = result.data(runtime);
        auto resultPreventGC =
            std::make_shared<jsi::ArrayBuffer>(std::move(result));

        auto offset = (int)arguments[1].asNumber();
        auto size = arguments[2].asNumber();

        return react::createPromiseAsJSIValue(
            runtime, [=](jsi::Runtime &runtime,
                         std::shared_ptr<react::Promise> promise) {
              // TODO(Szymon) implement check prime once we have bignums
              this->runOnWorkerThread([=]() {
                if (RAND_bytes(resultData + offset, size) != 1) {
                  this->runOnJSThread([=]() {
                    promise->reject("Sth went wrong with RAND_bytes");
                  });
                }
                this->runOnJSThread([=]() {
                  promise->resolve(
                      jsi::ArrayBuffer(std::move(*resultPreventGC)));
                });
              });
            });
      }));

  this->fields.push_back(buildPair(
      "randomFillSync", JSIF([=]) {
        if (count != 3) {
          throw jsi::JSError(runtime,
                             "randomFillSync(..) expects exactly 4 arguments!");
        }

        auto result = arguments[0].asObject(runtime).getArrayBuffer(runtime);
        auto resultSize = result.size(runtime);
        auto *resultData = result.data(runtime);
        auto offset = (int)arguments[1].asNumber();
        auto size = arguments[2].asNumber();

        if (RAND_bytes(resultData + offset, size) != 1) {
          throw jsi::JSError(runtime, "Sth went wrong with RAND_bytes" +
                                          std::to_string(ERR_get_error()));
        }

        return result;
      }));
}

}  // namespace margelo
