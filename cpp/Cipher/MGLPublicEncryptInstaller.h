#ifndef MGLPublicEncryptInstaller_h
#define MGLPublicEncryptInstaller_h

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

FieldDefinition getPublicEncryptFieldDefinition(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);
}  // namespace margelo

#endif