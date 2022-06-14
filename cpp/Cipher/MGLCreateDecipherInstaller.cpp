#include "MGLCreateDecipherInstaller.h"

#include <memory>

#include "JSIUtils/MGLJSIMacros.h"
#include "MGLCipherHostObject.h"

using namespace facebook;

namespace margelo {

FieldDefinition getCreateDecipherFieldDefinition(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue) {
  return HOST_LAMBDA("createDecipher", {
    if (count < 1) {
      throw jsi::JSError(runtime, "Params object is required");
    }

    if (!arguments[0].isObject()) {
      throw jsi::JSError(runtime, "createCipher: Params needs to be an object");
    }

    auto params = arguments[0].getObject(runtime);

    if (!params.hasProperty(runtime, "cipher_type")) {
      throw jsi::JSError(runtime, "createCipher: cipher_type is required");
    }

    auto cipher_type = params.getProperty(runtime, "cipher_type")
                           .asString(runtime)
                           .utf8(runtime);

    if (!params.hasProperty(runtime, "cipher_key")) {
      throw jsi::JSError(runtime, "createCipher: cipher_key is required");
    }

    auto cipher_key = params.getProperty(runtime, "cipher_key")
                          .getObject(runtime)
                          .getArrayBuffer(runtime);

    if (!params.hasProperty(runtime, "auth_tag_len")) {
      throw jsi::JSError(runtime, "createCipher: auth_tag_len is required");
    }

    unsigned auto int auth_tag_len =
        (int)params.getProperty(runtime, "auth_tag_len").getNumber();

    if (params.hasProperty(runtime, "iv") &&
        !params.getProperty(runtime, "iv").isNull() &&
        !params.getProperty(runtime, "iv").isUndefined()) {  // createDecipheriv
      auto iv = params.getProperty(runtime, "iv")
                    .getObject(runtime)
                    .getArrayBuffer(runtime);
      auto hostObject = std::make_shared<MGLCipherHostObject>(
          cipher_type, &cipher_key, false, auth_tag_len, &iv, runtime,
          jsCallInvoker, workerQueue);

      return jsi::Object::createFromHostObject(runtime, hostObject);
    } else {
      auto hostObject = std::make_shared<MGLCipherHostObject>(
          cipher_type, &cipher_key, false, auth_tag_len, runtime, jsCallInvoker,
          workerQueue);

      return jsi::Object::createFromHostObject(runtime, hostObject);
    }
  });
}
}  // namespace margelo
