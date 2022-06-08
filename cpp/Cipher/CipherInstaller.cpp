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
    if (count < 2) {
      throw jsi::JSError(
          runtime, "createCipher: cipher type and cipher key are required");
    }

    if (!arguments[0].isString()) {
      throw jsi::JSError(runtime,
                         "createCipher: First argument ('cipher type') needs "
                         "to be a valid string");
    }

    if (!arguments[1].isObject() ||
        !arguments[1].getObject(runtime).isArrayBuffer(runtime)) {
      throw jsi::JSError(runtime,
                         "createCipher: Second argument ('cipher key') "
                         "has to be of type ArrayBuffer!");
    }

    auto cipher_type = arguments[0].asString(runtime).utf8(runtime);
    auto cipher_key = arguments[1].getObject(runtime).getArrayBuffer(runtime);

    auto hostObject = std::make_shared<CipherHostObject>(
        cipher_type, cipher_key, true, jsCallInvoker, workerQueue);

    return jsi::Object::createFromHostObject(runtime, hostObject);
  });
}
}  // namespace margelo
