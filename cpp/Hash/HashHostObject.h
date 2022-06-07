// Copyright 2022 Margelo
//  HashHostObject.h
//
//

#ifndef HashHostObject_h
#define HashHostObject_h

#include <jsi/jsi.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>

#include <memory>
#include <string>

#include "JSI Utils/SmartHostObject.h"

namespace margelo {

using namespace facebook;

class HashHostObject : public SmartHostObject {
 public:
  explicit HashHostObject(
      std::string hashAlgorithm, unsigned int md_len,
      std::shared_ptr<react::CallInvoker> jsCallInvoker,
      std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);

  explicit HashHostObject(
      HashHostObject *other, std::shared_ptr<react::CallInvoker> jsCallInvoker,
      std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);
  void installMethods();

  virtual ~HashHostObject();

 private:
  EVP_MD_CTX *mdctx_ = nullptr;
  unsigned int md_len_ = 0;
  char *digest_ = nullptr;
};
}  // namespace margelo

#endif /* HashHostObject_h */
