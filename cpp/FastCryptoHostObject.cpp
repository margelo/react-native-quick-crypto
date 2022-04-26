// Copyright 2022 Margelo
#include "FastCryptoHostObject.h"

#include <Hash/HashInstaller.h>
#include <ReactCommon/TurboModuleUtils.h>
#include <jsi/jsi.h>

#include <memory>
#include <vector>

#include "HMAC/HmacInstaller.h"
#include "Random/RandomHostObject.h"
#include "fastpbkdf2/Pbkdf2HostObject.h"

namespace margelo {

namespace jsi = facebook::jsi;

FastCryptoHostObject::FastCryptoHostObject(
  std::shared_ptr<react::CallInvoker> jsCallInvoker,
  std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue)
  : SmartHostObject(jsCallInvoker, workerQueue) {
  this->fields.push_back(getHmacFieldDefinition(jsCallInvoker, workerQueue));
  this->fields.push_back(getHashFieldDefinition(jsCallInvoker, workerQueue));
  this->fields.push_back(JSI_VALUE("pbkdf2", {
      auto hostObject =
	std::make_shared<Pbkdf2HostObject>(jsCallInvoker, workerQueue);
      return jsi::Object::createFromHostObject(runtime, hostObject);
    }));
  this->fields.push_back(JSI_VALUE("random", {
      auto hostObject =
	std::make_shared<RandomHostObject>(jsCallInvoker, workerQueue);
      return jsi::Object::createFromHostObject(runtime, hostObject);
    }));
}

}  // namespace margelo
