#include "CipherInstaller.h"

#include <memory>

#include "CipherHostObject.h"
#include "JSI Utils/JSIMacros.h"

using namespace facebook;

namespace margelo {

FieldDefinition getCipherFieldDefinition(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue) {
  return HOST_LAMBDA("createCipher", {
    // TODO(osp) Add arg validation
    // if()

    auto algorithm = arguments[0].asString(runtime).utf8(runtime);
    auto password = arguments[1].asString(runtime).utf8(runtime);

    auto hostObject = std::make_shared<CipherHostObject>(
        algorithm, password, true, jsCallInvoker, workerQueue);

    return jsi::Object::createFromHostObject(runtime, hostObject);
  });
}
}  // namespace margelo
