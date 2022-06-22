//
//  MGLGenerateKeyPairInstaller.cpp
//  react-native-quick-crypto
//
//  Created by Oscar on 22.06.22.
//

#include "MGLGenerateKeyPairInstaller.h"

#include <iostream>
#include <memory>

#ifdef ANDROID
#include "JSIUtils/MGLJSIMacros.h"
#else
#include "MGLJSIMacros.h"
#endif
#include "MGLRsa.h"

using namespace facebook;

namespace margelo {

FieldDefinition getGenerateKeyPairFieldDefinition(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue) {
  return HOST_LAMBDA("generateKeyPair", {
    bool isAsync = arguments[0].getBool();

    RSAKeyVariant variant = (RSAKeyVariant)(int)arguments[1].asNumber();

    std::cout << "Received variant" << variant << " and isAsync " << isAsync
              << std::endl;
    return {};
  });
}
}  // namespace margelo
