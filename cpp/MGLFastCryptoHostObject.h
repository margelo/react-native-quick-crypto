// Copyright 2022 Margelo
#ifndef CPP_FASTCRYPTOHOSTOBJECT_H_
#define CPP_FASTCRYPTOHOSTOBJECT_H_

#include <ReactCommon/CallInvoker.h>
#include <jsi/jsi.h>

#include <memory>

#include "JSI Utils/MGLSmartHostObject.h"
#include "JSI Utils/MGLTypedArray.h"
#include "Utils/MGLDispatchQueue.h"

namespace margelo {

namespace jsi = facebook::jsi;
namespace react = facebook::react;

class JSI_EXPORT MGLFastCryptoHostObject : public MGLSmartHostObject {
 public:
  explicit MGLFastCryptoHostObject(
      std::shared_ptr<react::CallInvoker> jsCallInvoker,
      std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);

  virtual ~MGLFastCryptoHostObject() { invalidateJsiPropNameIDCache(); }
};

}  // namespace margelo

#endif  // CPP_FASTCRYPTOHOSTOBJECT_H_
