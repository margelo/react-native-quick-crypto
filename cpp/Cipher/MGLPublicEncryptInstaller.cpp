//
//  MGLPublicEncryptInstaller.cpp
//  react-native-fast-crypto
//
//  Created by Oscar on 17.06.22.
//

#include "MGLPublicEncryptInstaller.h"

#include <iostream>
#include <memory>

#include "MGLCipherKeys.h"

#ifdef ANDROID
#include "JSIUtils/MGLJSIMacros.h"
#else
#include "MGLJSIMacros.h"
#endif

using namespace facebook;

namespace margelo {

FieldDefinition getCreatePublicEncryptFieldDefinition(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue) {
  return HOST_LAMBDA("publicEncrypt", {
    // TODO(osp) validation of params
    //    if (count < 1) {
    //      throw jsi::JSError(runtime, "Params object is required");
    //    }
    //
    //    if (!arguments[0].isObject()) {
    //      throw jsi::JSError(runtime, "createCipher: Params needs to be an
    //      object");
    //    }
    //
    //    auto params = arguments[0].getObject(runtime);

    unsigned int offset = 0;

    ManagedEVPPKey pkey = ManagedEVPPKey::GetPublicOrPrivateKeyFromJs(
        runtime, arguments, &offset);
    if (!pkey) {
      std::cout << "did not generate key!" << std::endl;
      return {};
    }

    std::cout << "offset " << offset << std::endl;

    return {};
  });
}
}  // namespace margelo
