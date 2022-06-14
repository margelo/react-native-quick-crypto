//
// Created by Szymon on 25/02/2022.
//

#ifndef MGL_RANDOMHOSTOBJECT_H
#define MGL_RANDOMHOSTOBJECT_H

#include <memory>

#include "JSI Utils/MGLSmartHostObject.h"

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
