//
//  HMAC-JSI-Installer.m
//  PinkPanda
//
//  Created by Marc Rousavy on 31.10.21.
//

#include "HashInstaller.h"

#include "HashHostObject.h"
#include <openssl/hmac.h>
#include "JSI Utils/JSIMacros.h"

using namespace facebook;

namespace margelo {

FieldDefinition getHashFieldDefinition(std::shared_ptr<react::CallInvoker> jsCallInvoker,
                                       std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue) {
  // createHash(hashAlgorithm: 'sha1' | 'sha256' | 'sha512')
  return HOST_LAMBDA("createHash", {
      if (count != 1 and count != 2) {
	    throw jsi::JSError(runtime, "createHmac(..) expects 1-2 arguments!");
      }

      auto hashAlgorithm = arguments[0].asString(runtime).utf8(runtime);
      unsigned int md_len = -1;
      if (!arguments[1].isUndefined()) {
          md_len = (unsigned int) arguments[1].asNumber();
      }


      auto hostObject = std::make_shared<HashHostObject>(hashAlgorithm,
                                                         md_len,
                                                         jsCallInvoker,
                                                         workerQueue);
      return jsi::Object::createFromHostObject(runtime, hostObject);
    });
}
}
