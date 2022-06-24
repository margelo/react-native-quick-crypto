//
//  MGLGenerateKeyPairInstaller.cpp
//  react-native-quick-crypto
//
//  Created by Oscar on 22.06.22.
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
        bool isAsync = arguments[0].getBool();

        // For asynchronisity I'm skipping the MGLDispatchQueue for now
        // But in the future a thread pool is necessary to avoid creating too
        // many threads

        return generateRSAKeyPair(runtime, arguments);
      });
}
}  // namespace margelo
