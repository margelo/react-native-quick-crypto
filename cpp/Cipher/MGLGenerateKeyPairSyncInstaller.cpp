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
        auto publicKey = toJSI(runtime, keys.first);
        auto privateKey = toJSI(runtime, keys.second);
        return jsi::Array::createWithElements(
            runtime, jsi::Value::undefined(), publicKey, privateKey);
      });
}
}  // namespace margelo
