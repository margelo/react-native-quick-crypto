//
//  MGLGenerateKeyPairInstaller.cpp
//  react-native-quick-crypto
//
//  Created by Oscar on 22.06.22.
//

#include "MGLGenerateKeyPairSyncInstaller.h"

#include <iostream>
#include <memory>
#include <utility>

#include "MGLRsa.h"

#ifdef ANDROID
#include "JSIUtils/MGLJSIMacros.h"
#include "JSIUtils/MGLJSIUtils.h"
#include "JSIUtils/MGLTypedArray.h"
#else
#include "MGLJSIMacros.h"
#include "MGLJSIUtils.h"
#include "MGLTypedArray.h"
#endif

using namespace facebook;

namespace margelo {

// Current implementation only supports RSA schemes (check line config.variant =
// ) As more encryption schemes are added this will require an abstraction that
// supports more schemes
FieldDefinition getGenerateKeyPairSyncFieldDefinition(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue) {
  return buildPair(
      "generateKeyPairSync", JSIF([=]) {
        auto config = std::make_shared<RsaKeyPairGenConfig>(
            prepareRsaKeyGenConfig(runtime, arguments));
        auto keys = generateRSAKeyPair(runtime, std::move(config));
        if (keys.first.isString && keys.second.isString) {
          auto publicKey =
              jsi::String::createFromUtf8(runtime, keys.first.stringValue);
          auto privateKey =
              jsi::String::createFromUtf8(runtime, keys.second.stringValue);
          return jsi::Array::createWithElements(
              runtime, jsi::Value::undefined(), publicKey, privateKey);
        } else {
          MGLTypedArray<MGLTypedArrayKind::Uint8Array> publicKeyBuffer(
              runtime, keys.first.vectorValue);
          MGLTypedArray<MGLTypedArrayKind::Uint8Array> privateKeyBuffer(
              runtime, keys.second.vectorValue);

          return jsi::Array::createWithElements(
              runtime, jsi::Value::undefined(), publicKeyBuffer,
              privateKeyBuffer);
        }
      });
}
}  // namespace margelo
