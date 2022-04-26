//
// Created by Szymon on 25/02/2022.
//

#ifndef FASTCRYPTOEXAMPLE_PBKDF2HOSTOBJECT_H
#define FASTCRYPTOEXAMPLE_PBKDF2HOSTOBJECT_H

#include "JSI Utils/SmartHostObject.h"
#include "fastpbkdf2/fastpbkdf2.h"

namespace margelo {
namespace jsi = facebook::jsi;

class Pbkdf2HostObject : public SmartHostObject {
public:
Pbkdf2HostObject(std::shared_ptr<react::CallInvoker> jsCallInvoker,
                 std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);
};

}  // namespace margelo
#endif  // FASTCRYPTOEXAMPLE_PBKDF2HOSTOBJECT_H
