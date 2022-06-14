#include <jsi/jsi.h>

#include <memory>

#include "JSI Utils/MGLSmartHostObject.h"

namespace margelo {
namespace jsi = facebook::jsi;

FieldDefinition getCreateCipherFieldDefinition(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);
}  // namespace margelo
