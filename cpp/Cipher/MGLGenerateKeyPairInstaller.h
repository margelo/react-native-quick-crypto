
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

#include "MGLKeys.h"

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

namespace margelo {

FieldDefinition getGenerateKeyPairFieldDefinition(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);
}  // namespace margelo

#endif /* MGLGenerateKeyPairInstaller_hpp */
