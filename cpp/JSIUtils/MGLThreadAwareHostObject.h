//
// Created by Szymon on 24/02/2022.
//

#ifndef MGL_THREADAWAREHOSTOBJECT_H
#define MGL_THREADAWAREHOSTOBJECT_H

#include <ReactCommon/CallInvoker.h>
#include <jsi/jsi.h>

#include <memory>

#ifdef ONANDROID
#include "Utils/MGLDispatchQueue.h"
#else
#include "../Utils/MGLDispatchQueue.h"
#endif

namespace margelo {

namespace jsi = facebook::jsi;
namespace react = facebook::react;

class JSI_EXPORT MGLThreadAwareHostObject : public jsi::HostObject {
 public:
  explicit MGLThreadAwareHostObject(
      std::shared_ptr<react::CallInvoker> jsCallInvoker,
      std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue)
      : weakJsCallInvoker(jsCallInvoker), dispatchQueue(workerQueue) {}

  virtual ~MGLThreadAwareHostObject() {}

  void runOnWorkerThread(std::function<void(void)> &&job);
  void runOnJSThread(std::function<void(void)> &&job);

 protected:
  std::weak_ptr<react::CallInvoker> weakJsCallInvoker;
  std::shared_ptr<DispatchQueue::dispatch_queue> dispatchQueue;
};

}  // namespace margelo

#endif  // MGL_THREADAWAREHOSTOBJECT_H
