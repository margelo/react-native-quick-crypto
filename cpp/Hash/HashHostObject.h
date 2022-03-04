// Copyright 2022 Margelo
//  HashHostObject.h
//
//

#ifndef HashHostObject_h
#define HashHostObject_h

#include <jsi/jsi.h>
#include <string>
#include <openssl/hmac.h>
#include "JSI Utils/SmartHostObject.h"

namespace margelo {

using namespace facebook;

class HashHostObject : public SmartHostObject {

public:
explicit HashHostObject(std::string hashAlgorithm,
                        unsigned int md_len,
                        std::shared_ptr<react::CallInvoker> jsCallInvoker,
                        std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);
virtual ~HashHostObject();
    EVPMDPointer mdctx_ {};
    unsigned int md_len_ = 0;
    unsigned char * digest_ = nullptr;
private:


};
}

#endif /* HashHostObject_h */
