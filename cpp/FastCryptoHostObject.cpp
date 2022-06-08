// Copyright 2022 Margelo
#include "FastCryptoHostObject.h"

#include <Hash/HashInstaller.h>
#include <ReactCommon/TurboModuleUtils.h>
#include <jsi/jsi.h>

#include <memory>
#include <vector>

#include "Cipher/CipherInstaller.h"
#include "HMAC/HmacInstaller.h"
#include "Random/RandomHostObject.h"
#include "fastpbkdf2/Pbkdf2HostObject.h"

namespace margelo {

namespace jsi = facebook::jsi;

FastCryptoHostObject::FastCryptoHostObject(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue)
    : SmartHostObject(jsCallInvoker, workerQueue) {
  // HmacInstaller
  this->fields.push_back(getHmacFieldDefinition(jsCallInvoker, workerQueue));

  // HashInstaller
  this->fields.push_back(getHashFieldDefinition(jsCallInvoker, workerQueue));

  // CipherInstaller
  this->fields.push_back(getCipherFieldDefinition(jsCallInvoker, workerQueue));

  // Pbkdf2HostObject
  this->fields.push_back(JSI_VALUE("pbkdf2", {
    auto hostObject =
        std::make_shared<Pbkdf2HostObject>(jsCallInvoker, workerQueue);
    return jsi::Object::createFromHostObject(runtime, hostObject);
  }));

  // RandomHostObject
  this->fields.push_back(JSI_VALUE("random", {
    auto hostObject =
        std::make_shared<RandomHostObject>(jsCallInvoker, workerQueue);
    return jsi::Object::createFromHostObject(runtime, hostObject);
  }));
}

}  // namespace margelo
