//
// Created by Szymon on 25/02/2022.
//

#include <JSI Utils/TypedArray.h>
#include "Pbkdf2HostObject.h"

namespace margelo {
namespace jsi = facebook::jsi;
namespace react = facebook::react;

Pbkdf2HostObject::Pbkdf2HostObject(std::shared_ptr<react::CallInvoker> jsCallInvoker,
                                   std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue) :
  SmartHostObject(jsCallInvoker, workerQueue) {
  this->fields.push_back(HOST_LAMBDA("pbkdf2", {
      if (count != 5) {
	throw jsi::JSError(runtime, "fastpbkdf2(..) expects exactly 5 arguments!");
      }

      auto password = arguments[0].asObject(runtime).getArrayBuffer(runtime);
      auto passwordSize = password.size(runtime);
      auto * passwordData = password.data(runtime);
      auto passwordPreventGC = std::make_shared<jsi::ArrayBuffer>(std::move(password));

      auto salt = arguments[1].asObject(runtime).getArrayBuffer(runtime);
      auto saltSize = salt.size(runtime);
      auto * saltData = salt.data(runtime);
      auto saltPreventGC = std::make_shared<jsi::ArrayBuffer>(std::move(salt));

      auto iterations = arguments[2].asNumber();
      auto keyLength = arguments[3].asNumber();
      auto hashAlgorithm = arguments[4].asString(runtime).utf8(runtime);

      auto resultArray = TypedArray<TypedArrayKind::Uint8Array>(runtime, static_cast<size_t>(keyLength));
      auto result = resultArray.getBuffer(runtime);
      auto resultSize = result.size(runtime);
      auto * resultData = result.data(runtime);
      auto resultPreventGC = std::make_shared<jsi::ArrayBuffer>(std::move(result));

      return react::createPromiseAsJSIValue(runtime, [=](jsi::Runtime &runtime,
                                                         std::shared_ptr<react::Promise> promise) {
	// TODO(Szymon) implement proper errors
	this->runOnWorkerThread([=]() {
	  if (hashAlgorithm == "sha1") {
	    fastpbkdf2_hmac_sha1(passwordData, passwordSize,
	                         saltData, saltSize,
	                         static_cast<uint32_t>(iterations),
	                         resultData, resultSize);
	  } else if (hashAlgorithm == "sha256") {
	    fastpbkdf2_hmac_sha256(passwordData, passwordSize,
	                           saltData, saltSize,
	                           static_cast<uint32_t>(iterations),
	                           resultData, resultSize);
	  } else if (hashAlgorithm == "sha512") {
	    fastpbkdf2_hmac_sha512(passwordData, passwordSize,
	                           saltData, saltSize,
	                           static_cast<uint32_t>(iterations),
	                           resultData, resultSize);
	  }
	  this->runOnJSThread([=]() {
	    promise->resolve(jsi::ArrayBuffer(std::move(*resultPreventGC)));
	    auto preventGC = passwordPreventGC;
	    auto preventGC2 = saltPreventGC;
	  });
	});
      });



      return resultArray;
    }));

  this->fields.push_back(HOST_LAMBDA("pbkdf2Sync", {
      if (count != 5) {
	throw jsi::JSError(runtime, "fastpbkdf2Sync(..) expects exactly 5 arguments!");
      }

      auto password = arguments[0].asObject(runtime).getArrayBuffer(runtime);
      auto salt = arguments[1].asObject(runtime).getArrayBuffer(runtime);
      auto iterations = arguments[2].asNumber();
      auto keyLength = arguments[3].asNumber();
      auto hashAlgorithm = arguments[4].asString(runtime).utf8(runtime);

      auto resultArray = TypedArray<TypedArrayKind::Uint8Array>(runtime, static_cast<size_t>(keyLength));
      auto result = resultArray.getBuffer(runtime);

      if (hashAlgorithm == "sha1") {
	fastpbkdf2_hmac_sha1(password.data(runtime), password.size(runtime),
	                     salt.data(runtime), salt.size(runtime),
	                     static_cast<uint32_t>(iterations),
	                     result.data(runtime), result.size(runtime));
      } else if (hashAlgorithm == "sha256") {
	fastpbkdf2_hmac_sha256(password.data(runtime), password.size(runtime),
	                       salt.data(runtime), salt.size(runtime),
	                       static_cast<uint32_t>(iterations),
	                       result.data(runtime), result.size(runtime));
      } else if (hashAlgorithm == "sha512") {
	fastpbkdf2_hmac_sha512(password.data(runtime), password.size(runtime),
	                       salt.data(runtime), salt.size(runtime),
	                       static_cast<uint32_t>(iterations),
	                       result.data(runtime), result.size(runtime));
      } else {
	throw jsi::JSError(runtime, "Invalid hash-algorithm!");
      }

      return resultArray;
    }));
}

}  // namespace margelo