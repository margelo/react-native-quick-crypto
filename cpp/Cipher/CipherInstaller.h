#include <jsi/jsi.h>

#include <memory>

#include "JSI Utils/SmartHostObject.h"

namespace margelo {
namespace jsi = facebook::jsi;

FieldDefinition getCipherFieldDefinition(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);
}  // namespace margelo
