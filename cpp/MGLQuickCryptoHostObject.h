// Copyright 2022 Margelo
#ifndef CPP_FASTCRYPTOHOSTOBJECT_H_
#define CPP_FASTCRYPTOHOSTOBJECT_H_

#include <ReactCommon/CallInvoker.h>
#include <jsi/jsi.h>

#include <memory>

#include "JSIUtils/MGLSmartHostObject.h"
#include "JSIUtils/MGLTypedArray.h"
#include "Utils/MGLDispatchQueue.h"

namespace margelo {

namespace jsi = facebook::jsi;
namespace react = facebook::react;

class JSI_EXPORT MGLQuickCryptoHostObject : public MGLSmartHostObject {
 public:
  explicit MGLQuickCryptoHostObject(
      std::shared_ptr<react::CallInvoker> jsCallInvoker,
      std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);

  virtual ~MGLQuickCryptoHostObject() {}
};

}  // namespace margelo

#endif  // CPP_FASTCRYPTOHOSTOBJECT_H_
