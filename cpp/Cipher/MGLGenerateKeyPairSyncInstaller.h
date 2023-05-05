//
//  MGLGenerateKeyPairInstaller.hpp
//  react-native-quick-crypto
//
//  Created by Oscar on 22.06.22.
//

#ifndef MGLGenerateKeyPairSyncInstaller_hpp
#define MGLGenerateKeyPairSyncInstaller_hpp

#include <jsi/jsi.h>

#include <memory>

#ifdef ANDROID
#include "Cipher/MGLRsa.h"
#include "Cipher/MGLX25519.h"
#include "JSIUtils/MGLSmartHostObject.h"
#include "Utils/MGLUtils.h"
#else
#include "MGLRsa.h"
#include "MGLSmartHostObject.h"
#include "MGLUtils.h"
#include "MGLX25519.h"
#endif
#include "MGLKeys.h"

namespace margelo {

// https://nodejs.org/api/crypto.html go to generateKeyPair
/// It's signature is:
/// generateKeyPair(type: string, options: record, callback: (error, publicKey,
/// privateKey))
FieldDefinition getGenerateKeyPairSyncFieldDefinition(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);
}  // namespace margelo

#endif /* MGLGenerateKeyPairInstaller_hpp */
