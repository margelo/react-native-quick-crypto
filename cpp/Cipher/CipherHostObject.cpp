//
// Created by Oscar on 07.06.22.
//
#include "CipherHostObject.h"

#include <openssl/evp.h>

#include <memory>
#include <string>

#define OUT

namespace margelo {

using namespace facebook;
namespace jsi = facebook::jsi;

CipherHostObject::CipherHostObject(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue)
    : SmartHostObject(jsCallInvoker, workerQueue) {
  installMethods();
}

CipherHostObject::CipherHostObject(
    const std::string &algorithm, const std::string &password, bool isCipher,
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue)
    : SmartHostObject(jsCallInvoker, workerQueue) {
  installMethods();
}

void CipherHostObject::installMethods() {
  // TODO(osp) implement
}
}  // namespace margelo
