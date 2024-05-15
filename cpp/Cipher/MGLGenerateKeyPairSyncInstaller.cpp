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
#include "webcrypto/crypto_ec.h"
#else
#include "MGLJSIMacros.h"
#include "MGLJSIUtils.h"
#include "MGLTypedArray.h"
#include "crypto_ec.h"
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
        std::pair<jsi::Value, jsi::Value> keys;
        KeyVariant variant =
            static_cast<KeyVariant>((int)arguments[0].asNumber());

            // switch on variant to get proper config/genKeyPair
            if (variant == kvRSA_SSA_PKCS1_v1_5 ||
                variant == kvRSA_PSS ||
                variant == kvRSA_OAEP
            ) {
                auto config = std::make_shared<RsaKeyPairGenConfig>(
                  prepareRsaKeyGenConfig(runtime, arguments));
                auto keys = generateRsaKeyPair(runtime, std::move(config));
            } else
            if (variant == kvEC) {
                auto config = std::make_shared<EcKeyPairGenConfig>(
                prepareEcKeyGenConfig(runtime, arguments));
                keys = generateEcKeyPair(runtime, config);
            } else {
                throw std::runtime_error("KeyVariant not implemented: " + variant);
            }
        // keys.first = publicKey   keys.second = privateKey
        return jsi::Array::createWithElements(
            runtime, jsi::Value::undefined(), keys.first, keys.second);
      });
}
}  // namespace margelo
