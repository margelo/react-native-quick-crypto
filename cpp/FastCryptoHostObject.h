// Copyright 2022 Margelo
#ifndef CPP_FASTCRYPTOHOSTOBJECT_H_
#define CPP_FASTCRYPTOHOSTOBJECT_H_

#include <jsi/jsi.h>
#import <ReactCommon/CallInvoker.h>
#include <memory>
#include "Utils/DispatchQueue.h"
#include "JSI Utils/SmartHostObject.h"

namespace margelo {

namespace jsi = facebook::jsi;
namespace react = facebook::react;

class JSI_EXPORT FastCryptoHostObject : public SmartHostObject {
public:
explicit FastCryptoHostObject(std::shared_ptr<react::CallInvoker> jsCallInvoker,
                              std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);

virtual ~FastCryptoHostObject() {
}
};

}  // namespace margelo

#endif  // CPP_FASTCRYPTOHOSTOBJECT_H_
