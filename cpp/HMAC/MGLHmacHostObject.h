//
//  HmacHostObject.h
//
//  Created by Marc Rousavy on 22.02.22.
//

#ifndef MGLHmacHostObject_h
#define MGLHmacHostObject_h

#include <jsi/jsi.h>
#include <openssl/hmac.h>

#include <memory>
#include <string>

#include "JSI Utils/MGLSmartHostObject.h"

namespace margelo {

using namespace facebook;

class MGLHmacHostObject : public MGLSmartHostObject {
 public:
  explicit MGLHmacHostObject(
      const std::string &hashAlgorithm, jsi::Runtime &runtime,
      jsi::ArrayBuffer &key, std::shared_ptr<react::CallInvoker> jsCallInvoker,
      std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);
  virtual ~MGLHmacHostObject();

 private:
  HMAC_CTX *context;
};
}  // namespace margelo

#endif /* MGLHmacHostObject_h */
