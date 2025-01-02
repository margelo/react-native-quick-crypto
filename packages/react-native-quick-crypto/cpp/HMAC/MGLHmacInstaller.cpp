//
//  HMAC-JSI-Installer.m
//  PinkPanda
//
//  Created by Marc Rousavy on 31.10.21.
//

#include "MGLHmacInstaller.h"

#include <openssl/hmac.h>

#ifdef ANDROID
#include "JSIUtils/MGLJSIMacros.h"
#include "MGLHmacHostObject.h"
#else
#include "MGLHmacHostObject.h"
#include "MGLJSIMacros.h"
#endif

using namespace facebook;

namespace margelo {

FieldDefinition getHmacFieldDefinition(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue) {
  // createHmac(hashAlgorithm: 'sha1' | 'sha256' | 'sha512',
  //            key: string)
  return HOST_LAMBDA("createHmac", {
    if (count != 2) {
      throw jsi::JSError(runtime,
                         "createHmac(..) expects exactly 2 arguments!");
    }

    auto hashAlgorithm = arguments[0].asString(runtime).utf8(runtime);
    auto key = arguments[1].getObject(runtime).getArrayBuffer(runtime);

    auto hostObject = std::make_shared<MGLHmacHostObject>(
        hashAlgorithm, runtime, key, jsCallInvoker, workerQueue);
    return jsi::Object::createFromHostObject(runtime, hostObject);
  });
}
}  // namespace margelo
