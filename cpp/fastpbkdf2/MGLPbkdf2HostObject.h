//
// Created by Szymon on 25/02/2022.
//

#ifndef MGL_PBKDF2HOSTOBJECT_H
#define MGL_PBKDF2HOSTOBJECT_H

#include <memory>

#include "JSIUtils/MGLSmartHostObject.h"
#include "fastpbkdf2/fastpbkdf2.h"

namespace margelo {
namespace jsi = facebook::jsi;

class MGLPbkdf2HostObject : public MGLSmartHostObject {
 public:
  MGLPbkdf2HostObject(
      std::shared_ptr<react::CallInvoker> jsCallInvoker,
      std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);
};

}  // namespace margelo
#endif  // MGL_PBKDF2HOSTOBJECT_H
