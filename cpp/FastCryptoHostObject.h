// Copyright 2022 Margelo
#ifndef CPP_FASTCRYPTOHOSTOBJECT_H_
#define CPP_FASTCRYPTOHOSTOBJECT_H_

#include <ReactCommon/CallInvoker.h>
#include <jsi/jsi.h>

#include <memory>

#include "JSI Utils/SmartHostObject.h"
#include "JSI Utils/TypedArray.h"
#include "Utils/DispatchQueue.h"

namespace margelo {

namespace jsi = facebook::jsi;
namespace react = facebook::react;

class JSI_EXPORT FastCryptoHostObject : public SmartHostObject {
 public:
  explicit FastCryptoHostObject(
      std::shared_ptr<react::CallInvoker> jsCallInvoker,
      std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);

  virtual ~FastCryptoHostObject() { invalidateJsiPropNameIDCache(); }
};

}  // namespace margelo

#endif  // CPP_FASTCRYPTOHOSTOBJECT_H_
