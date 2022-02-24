//
//  HMAC-JSI-Installer.m
//  PinkPanda
//
//  Created by Marc Rousavy on 31.10.21.
//

#include "HMAC-JSI-Installer.h"

#include "HmacHostObject.h"
#include <openssl/hmac.h>

using namespace facebook;

namespace fastHMAC {

void installInRuntime(jsi::Runtime& runtime) {
  // createHmac(hashAlgorithm: 'sha1' | 'sha256' | 'sha512',
  //            key: string)
  auto func = jsi::Function::createFromHostFunction(runtime,
                                                    jsi::PropNameID::forAscii(runtime, "func"),
                                                    2,
                                                    [](jsi::Runtime& runtime,
                                                       const jsi::Value&,
                                                       const jsi::Value* arguments,
                                                       size_t count) -> jsi::Value {
      if (count != 2) {
	throw jsi::JSError(runtime, "createHmac(..) expects exactly 2 arguments!");
      }

      auto hashAlgorithm = arguments[0].asString(runtime).utf8(runtime);
      auto key = arguments[1].asString(runtime).utf8(runtime);

      auto hostObject = std::make_shared<HmacHostObject>(hashAlgorithm, key);
      return jsi::Object::createFromHostObject(runtime, hostObject);
    });
  runtime.global().setProperty(runtime, "createHmac", std::move(func));
}
}
