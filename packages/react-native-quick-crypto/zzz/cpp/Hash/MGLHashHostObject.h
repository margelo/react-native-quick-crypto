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

#ifdef ANDROID
#include "JSIUtils/MGLSmartHostObject.h"
#else
#include "MGLSmartHostObject.h"
#endif

namespace margelo {

using namespace facebook;

class MGLHashHostObject : public MGLSmartHostObject {
 public:
  explicit MGLHashHostObject(
      std::string hashAlgorithm, unsigned int md_len,
      std::shared_ptr<react::CallInvoker> jsCallInvoker,
      std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);

  explicit MGLHashHostObject(
      MGLHashHostObject *other,
      std::shared_ptr<react::CallInvoker> jsCallInvoker,
      std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);
  void installMethods();

  virtual ~MGLHashHostObject();

 private:
  EVP_MD_CTX *mdctx_ = nullptr;
  unsigned int md_len_ = 0;
  char *digest_ = nullptr;
};
}  // namespace margelo

#endif /* MGLHashHostObject_h */
