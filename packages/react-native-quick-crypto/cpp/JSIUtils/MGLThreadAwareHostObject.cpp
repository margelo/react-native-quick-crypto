//
// Created by Szymon on 24/02/2022.
//

#include "MGLThreadAwareHostObject.h"

#include <utility>

namespace margelo {

namespace jsi = facebook::jsi;

void MGLThreadAwareHostObject::runOnWorkerThread(std::function<void()> &&job) {
  this->dispatchQueue->dispatch(job);
}

void MGLThreadAwareHostObject::runOnJSThread(std::function<void()> &&job) {
  auto callInvoker = this->weakJsCallInvoker.lock();
  if (callInvoker != nullptr) {
    callInvoker->invokeAsync(std::move(job));
  }
}

}  // namespace margelo
