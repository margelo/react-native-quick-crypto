#include <jsi/jsi.h>

#include <memory>

#include "JSIUtils/MGLSmartHostObject.h"

namespace margelo {
namespace jsi = facebook::jsi;

FieldDefinition getCreateDecipherFieldDefinition(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);
}  // namespace margelo
