//
//  MGLSignInstaller.cpp
//  DoubleConversion
//
//  Created by Oscar on 30.06.22.
//

#include "MGLSignInstaller.h"
#ifdef ANDROID
#include "JSIUtils/MGLJSIMacros.h"
#else
#include "MGLJSIMacros.h"
#endif

namespace margelo {

FieldDefinition getCreateSignFieldDefinition(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue) {
  return buildPair(
      "createSign", JSIF([=]) { return {}; });
}

}  // namespace margelo
