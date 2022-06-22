//
//  MGLGenerateKeyPairInstaller.hpp
//  react-native-quick-crypto
//
//  Created by Oscar on 22.06.22.
//

#ifndef MGLGenerateKeyPairInstaller_hpp
#define MGLGenerateKeyPairInstaller_hpp

#include <jsi/jsi.h>

#include <memory>

#ifdef ANDROID
#include "JSIUtils/MGLSmartHostObject.h"
#else
#include "MGLSmartHostObject.h"
#endif

namespace margelo {
namespace jsi = facebook::jsi;

// https://nodejs.org/api/crypto.html go to generateKeyPair
/// It's signature is:
/// generateKeyPair(type: string, options: record, callback: (error, publicKey,
/// privateKey))
FieldDefinition getHashFieldDefinition(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);
}  // namespace margelo

#endif /* MGLGenerateKeyPairInstaller_hpp */
