//
// Created by Oscar on 07.06.22.
//
#include "CipherHostObject.h"

#include <openssl/evp.h>

#include <memory>
#include <string>

#define OUT

// TODO(osp) Some of the code is inspired or copied from node-js, check if
// attribution is needed
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
    const std::string &cipher_type, jsi::ArrayBuffer *cipher_key, bool isCipher,
    jsi::Runtime &runtime, std::shared_ptr<react::CallInvoker> jsCallInvoker,
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

  unsigned char key[EVP_MAX_KEY_LENGTH];
  unsigned char iv[EVP_MAX_IV_LENGTH];

  //    int key_len = EVP_BytesToKey(cipher,
  //                                 EVP_md5(),
  //                                 nullptr,
  //                                 cipher_key.data(runtime),
  //                                 cipher_key.size(runtime),
  //                                 1,
  //                                 key,
  //                                 iv);

  // TODO(osp) this looks like a macro, check if necessary
  // CHECK_NE(key_len, 0);

  // TODO(osp) this seems like a runtime check
  //  const int mode = EVP_CIPHER_mode(cipher);
  //  if (isCipher && (mode == EVP_CIPH_CTR_MODE ||
  //                           mode == EVP_CIPH_GCM_MODE ||
  //                           mode == EVP_CIPH_CCM_MODE)) {
  //    // Ignore the return value (i.e. possible exception) because we are
  //    // not calling back into JS anyway.
  //    ProcessEmitWarning(env(),
  //                       "Use Cipheriv for counter mode of %s",
  //                       cipher_type);
  //  }

  //  CommonInit(cipher_type, cipher, key, key_len, iv,
  //             EVP_CIPHER_iv_length(cipher), auth_tag_len);

  // TODO(osp) temp code only for committing only
  commonInit(
      cipher_type.c_str(), cipher, cipher_key->data(runtime),
      cipher_key->size(runtime),
      reinterpret_cast<const unsigned char *>(EVP_CIPHER_iv_length(cipher)), 9,
      9);
  installMethods();
}

void CipherHostObject::commonInit(const char *cipher_type,
                                  const EVP_CIPHER *cipher,
                                  const unsigned char *key, int key_len,
                                  const unsigned char *iv, int iv_len,
                                  unsigned int auth_tag_len) {
  // TODO(osp) check for this macro
  //  CHECK(!ctx_);
  if (ctx_ == nullptr) {
    ctx_ = EVP_CIPHER_CTX_new();
  }

  const int mode = EVP_CIPHER_mode(cipher);
  if (mode == EVP_CIPH_WRAP_MODE)
    EVP_CIPHER_CTX_set_flags(ctx_, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
}

void CipherHostObject::installMethods() {
  // TODO(osp) implement
}
}  // namespace margelo
