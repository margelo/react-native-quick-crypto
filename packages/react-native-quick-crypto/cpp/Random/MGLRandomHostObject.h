//
// Created by Szymon on 25/02/2022.
//

#ifndef MGL_RANDOMHOSTOBJECT_H
#define MGL_RANDOMHOSTOBJECT_H

#include <memory>

#ifdef ANDROID
#include "JSIUtils/MGLSmartHostObject.h"
#else
#include "MGLSmartHostObject.h"
#endif

namespace margelo {
namespace jsi = facebook::jsi;

class MGLRandomHostObject : public MGLSmartHostObject {
 public:
  MGLRandomHostObject(
      std::shared_ptr<react::CallInvoker> jsCallInvoker,
      std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);
};

}  // namespace margelo
#endif  // MGL_RANDOMHOSTOBJECT_H
