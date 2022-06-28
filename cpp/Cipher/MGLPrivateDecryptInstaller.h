//
//  MGLPrivateDecryptInstaller.h
//  react-native-quick-crypto
//
//  Created by Oscar on 28.06.22.
//

#ifndef MGLPrivateDecryptInstaller_h
#define MGLPrivateDecryptInstaller_h

#include <jsi/jsi.h>
#include <openssl/evp.h>

#include <memory>

#ifdef ANDROID
#include "JSIUtils/MGLSmartHostObject.h"
#else
#include "MGLSmartHostObject.h"
#endif

namespace margelo {
namespace jsi = facebook::jsi;

FieldDefinition getPrivateDecryptFieldDefinition(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);
}  // namespace margelo

#endif /* MGLPrivateDecryptInstaller_h */
