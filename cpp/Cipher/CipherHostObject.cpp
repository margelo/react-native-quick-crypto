//
// Created by Oscar on 07.06.22.
//
#include "CipherHostObject.h"

#include <openssl/evp.h>

#include <memory>
#include <string>

#define OUT

namespace margelo {

namespace jsi = facebook::jsi;

CipherHostObject::CipherHostObject(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue)
    : SmartHostObject(jsCallInvoker, workerQueue) {
  installMethods();
}

CipherHostObject::CipherHostObject(
    CipherHostObject *other, std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue)
    : SmartHostObject(jsCallInvoker, workerQueue), isCipher_(other->isCipher_) {
  installMethods();
}

CipherHostObject::CipherHostObject(
    const std::string &cipher_type, const std::string &password, bool isCipher,
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue)
    : SmartHostObject(jsCallInvoker, workerQueue), isCipher_(isCipher) {
  // TODO(osp) is this needed on the SSL version we are using?
  // #if OPENSSL_VERSION_MAJOR >= 3
  //    if (EVP_default_properties_is_fips_enabled(nullptr)) {
  // #else
  //    if (FIPS_mode()) {
  // #endif
  //        return THROW_ERR_CRYPTO_UNSUPPORTED_OPERATION(env(),
  //                                                      "crypto.createCipher()
  //                                                      is not supported in
  //                                                      FIPS mode.");
  //    }

  const EVP_CIPHER *const cipher = EVP_get_cipherbyname(cipher_type.c_str());
  if (cipher == nullptr) throw std::runtime_error("Invalid Cipher Algorithm!");
  installMethods();
}

void CipherHostObject::installMethods() {
  // TODO(osp) implement
}
}  // namespace margelo
