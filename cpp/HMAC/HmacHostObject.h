//
//  HmacHostObject.h
//
//  Created by Marc Rousavy on 22.02.22.
//

#ifndef HmacHostObject_h
#define HmacHostObject_h

#include <jsi/jsi.h>
#include <openssl/hmac.h>

#include <string>

#include "JSI Utils/SmartHostObject.h"

namespace margelo {

using namespace facebook;

class HmacHostObject : public SmartHostObject {
 public:
  explicit HmacHostObject(
      const std::string& hashAlgorithm, jsi::Runtime& runtime,
      jsi::ArrayBuffer& key, std::shared_ptr<react::CallInvoker> jsCallInvoker,
      std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);
  virtual ~HmacHostObject();

 private:
  HMAC_CTX* context;
};
}  // namespace margelo

#endif /* HmacHostObject_h */
