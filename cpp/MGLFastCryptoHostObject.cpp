// Copyright 2022 Margelo
#include "MGLFastCryptoHostObject.h"

#include <Hash/MGLHashInstaller.h>
#include <ReactCommon/TurboModuleUtils.h>
#include <jsi/jsi.h>

#include <memory>
#include <vector>

#include "Cipher/MGLCreateCipherInstaller.h"
#include "Cipher/MGLCreateDecipherInstaller.h"
#include "HMAC/MGLHmacInstaller.h"
#include "Random/MGLRandomHostObject.h"
#include "fastpbkdf2/MGLPbkdf2HostObject.h"

namespace margelo {

namespace jsi = facebook::jsi;

MGLFastCryptoHostObject::MGLFastCryptoHostObject(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue)
    : MGLSmartHostObject(jsCallInvoker, workerQueue) {
  // HmacInstaller
  this->fields.push_back(getHmacFieldDefinition(jsCallInvoker, workerQueue));

  // HashInstaller
  this->fields.push_back(getHashFieldDefinition(jsCallInvoker, workerQueue));

  // CreateCipherInstaller
  this->fields.push_back(
      getCreateCipherFieldDefinition(jsCallInvoker, workerQueue));

  // CreateDecipherInstaller
  this->fields.push_back(
      getCreateDecipherFieldDefinition(jsCallInvoker, workerQueue));

  // Pbkdf2HostObject
  this->fields.push_back(JSI_VALUE("pbkdf2", {
    auto hostObject =
        std::make_shared<MGLPbkdf2HostObject>(jsCallInvoker, workerQueue);
    return jsi::Object::createFromHostObject(runtime, hostObject);
  }));

  // RandomHostObject
  this->fields.push_back(JSI_VALUE("random", {
    auto hostObject =
        std::make_shared<MGLRandomHostObject>(jsCallInvoker, workerQueue);
    return jsi::Object::createFromHostObject(runtime, hostObject);
  }));
}

}  // namespace margelo
