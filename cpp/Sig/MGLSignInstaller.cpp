//
//  MGLSignInstaller.cpp
//  DoubleConversion
//
//  Created by Oscar on 30.06.22.
//

#include "MGLSignInstaller.h"

#include "MGLSignHostObjects.h"
#ifdef ANDROID
#include "JSIUtils/MGLJSIMacros.h"
#else
#include "MGLJSIMacros.h"
#include "logs.h"
#endif

namespace margelo {

FieldDefinition getSignFieldDefinition(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue) {
  return buildPair(
      "createSign", JSIF([=]) {
        auto hostObject =
            std::make_shared<MGLSignHostObject>(jsCallInvoker, workerQueue);
        return jsi::Object::createFromHostObject(runtime, hostObject);
      });
}

}  // namespace margelo
