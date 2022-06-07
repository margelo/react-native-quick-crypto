//
// Created by Oscar on 07.06.22.
//

#ifndef FASTCRYPTOEXAMPLE_CIPHERHOSTOBJECT_H
#define FASTCRYPTOEXAMPLE_CIPHERHOSTOBJECT_H

#include <memory>

#include "JSI Utils/SmartHostObject.h"

namespace margelo {
namespace jsi = facebook::jsi;

class CipherHostObject : public SmartHostObject {
 public:
  CipherHostObject(std::shared_ptr<react::CallInvoker> jsCallInvoker,
                   std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);
};

}  // namespace margelo

#endif  // FASTCRYPTOEXAMPLE_CIPHERHOSTOBJECT_H
