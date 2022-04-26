//
// Created by Szymon on 24/02/2022.
//

#ifndef FASTCRYPTOEXAMPLE_THREADAWAREHOSTOBJECT_H
#define FASTCRYPTOEXAMPLE_THREADAWAREHOSTOBJECT_H

#include <ReactCommon/CallInvoker.h>
#include <jsi/jsi.h>

#ifdef ONANDROID
#include "Utils/DispatchQueue.h"
#else
#include "../Utils/DispatchQueue.h"
#endif

namespace margelo {

namespace jsi = facebook::jsi;
namespace react = facebook::react;

class JSI_EXPORT ThreadAwareHostObject : public jsi::HostObject {
public:
explicit ThreadAwareHostObject(
  std::shared_ptr<react::CallInvoker> jsCallInvoker,
  std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue)
  : weakJsCallInvoker(jsCallInvoker), dispatchQueue(workerQueue) {
}

virtual ~ThreadAwareHostObject() {
}

void runOnWorkerThread(std::function<void(void)>&& job);
void runOnJSThread(std::function<void(void)>&& job);

protected:
std::weak_ptr<react::CallInvoker> weakJsCallInvoker;
std::shared_ptr<DispatchQueue::dispatch_queue> dispatchQueue;
};

}  // namespace margelo

#endif  // FASTCRYPTOEXAMPLE_THREADAWAREHOSTOBJECT_H
