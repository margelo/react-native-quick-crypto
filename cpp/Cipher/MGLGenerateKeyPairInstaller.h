
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
#include "MGLCipherKeys.h"
#include "MGLRsa.h"
#include "MGLUtils.h"

namespace margelo {

FieldDefinition getGenerateKeyPairFieldDefinition(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);
}  // namespace margelo

#endif /* MGLGenerateKeyPairInstaller_hpp */
