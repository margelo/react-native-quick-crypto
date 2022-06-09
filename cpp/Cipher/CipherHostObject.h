//
// Created by Oscar on 07.06.22.
//

#ifndef CipherHostObject_h
#define CipherHostObject_h

#include <jsi/jsi.h>
#include <openssl/evp.h>

#include <memory>
#include <string>

#include "JSI Utils/SmartHostObject.h"

namespace margelo {

namespace jsi = facebook::jsi;

class CipherHostObject : public SmartHostObject {
 protected:
  enum CipherKind { kCipher, kDecipher };
  enum UpdateResult { kSuccess, kErrorMessageSize, kErrorState };
  enum AuthTagState { kAuthTagUnknown, kAuthTagKnown, kAuthTagPassedToOpenSSL };

 public:
  // TODO(osp)  Why does an empty constructor need to be here and not on
  // HashHostObject?
  explicit CipherHostObject(
      std::shared_ptr<react::CallInvoker> jsCallInvoker,
      std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);

  explicit CipherHostObject(
      CipherHostObject *other,
      std::shared_ptr<react::CallInvoker> jsCallInvoker,
      std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);

  explicit CipherHostObject(
      const std::string &cipher_type, jsi::ArrayBuffer *cipher_key,
      bool isCipher, unsigned int auth_tag_len, jsi::Runtime &runtime,
      std::shared_ptr<react::CallInvoker> jsCallInvoker,
      std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);

  void commonInit(jsi::Runtime &runtime, const char *cipher_type,
                  const EVP_CIPHER *cipher, const unsigned char *key,
                  int key_len, const unsigned char *iv, int iv_len,
                  unsigned int auth_tag_len);

  void installMethods();

  bool InitAuthenticated(const char *cipher_type, int iv_len,
                         unsigned int auth_tag_len);

  bool CheckCCMMessageLength(int message_len);

  bool IsAuthenticatedMode() const;

  bool MaybePassAuthTagToOpenSSL();

  virtual ~CipherHostObject() {}

 private:
  // TODO(osp) this is the node version, DeleteFnPtr seems to be some custom
  // wrapper, I guess useful for memory deallocation
  // DeleteFnPtr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free> ctx_;
  // For now I'm manually calling EVP_CIPHER_CTX_free in the implementation
  EVP_CIPHER_CTX *ctx_ = nullptr;
  bool isCipher_;
  bool pending_auth_failed_;
  char auth_tag_[EVP_GCM_TLS_TAG_LEN];
  AuthTagState auth_tag_state_;
  unsigned int auth_tag_len_;
  int max_message_size_;
};

}  // namespace margelo

#endif  // CipherHostObject_h
