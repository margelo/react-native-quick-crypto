//
//  HmacHostObject.h
//  PinkPanda
//
//  Created by Marc Rousavy on 22.02.22.
//

#ifndef HmacHostObject_h
#define HmacHostObject_h

#include <jsi/jsi.h>
#include <string>
#include <openssl/hmac.h>
#include "JSI Utils/SmartHostObject.h"

namespace margelo {

using namespace facebook;

class HmacHostObject : public SmartHostObject {

public:
explicit HmacHostObject(const std::string& hashAlgorithm,
                        const std::string& key,
                        std::shared_ptr<react::CallInvoker> jsCallInvoker,
                        std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);
virtual ~HmacHostObject();

private:
HMAC_CTX* context;

};
}

#endif /* HmacHostObject_h */
