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

class CipherHostObject : public SmartHostObject {
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
      const std::string &cipher_type, const std::string &password,
      bool isCipher, std::shared_ptr<react::CallInvoker> jsCallInvoker,
      std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);

  void installMethods();

  virtual ~CipherHostObject() {}

 private:
  EVP_CIPHER_CTX *ctx_ = nullptr;
  bool isCipher_;
};

}  // namespace margelo

#endif  // CipherHostObject_h
