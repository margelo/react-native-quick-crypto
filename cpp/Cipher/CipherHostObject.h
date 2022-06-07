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

using namespace facebook;

class CipherHostObject : public SmartHostObject {
 public:
  explicit CipherHostObject(
      const std::string &algorithm, const std::string &password, bool isCipher,
      std::shared_ptr<react::CallInvoker> jsCallInvoker,
      std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);

  explicit CipherHostObject(
      std::shared_ptr<react::CallInvoker> jsCallInvoker,
      std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);

  void installMethods();

  virtual ~CipherHostObject() {}

 private:
  EVP_CIPHER_CTX *ctx_ = nullptr;
};

}  // namespace margelo

#endif  // CipherHostObject_h
