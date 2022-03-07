// Copyright 2022 Margelo
#include "FastCryptoHostObject.h"
#include <ReactCommon/TurboModuleUtils.h>
#include <jsi/jsi.h>
#include <vector>
#include <memory>
#include <Hash/HashInstaller.h>
#include "HMAC/HmacInstaller.h"
#include "fastpbkdf2/Pbkdf2HostObject.h"
#include "Random/RandomHostObject.h"

namespace margelo {

namespace jsi = facebook::jsi;

FastCryptoHostObject::FastCryptoHostObject(std::shared_ptr<react::CallInvoker> jsCallInvoker,
                                           std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue) :
  SmartHostObject(jsCallInvoker, workerQueue) {

  this->fields.push_back(getHmacFieldDefinition(jsCallInvoker, workerQueue));
  this->fields.push_back(getHashFieldDefinition(jsCallInvoker, workerQueue));
  this->fields.push_back(JSI_VALUE("pbkdf2", {
      auto hostObject = std::make_shared<Pbkdf2HostObject>(jsCallInvoker,
                                                           workerQueue);
      return jsi::Object::createFromHostObject(runtime, hostObject);
    }));
  this->fields.push_back(JSI_VALUE("random", {
      auto hostObject = std::make_shared<RandomHostObject>(jsCallInvoker,
                                                           workerQueue);
      return jsi::Object::createFromHostObject(runtime, hostObject);
  }));
}

}  // namespace margelo
