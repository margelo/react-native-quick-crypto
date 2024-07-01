#include "crypto_keygen.h"

#ifdef ANDROID
#include "JSIUtils/MGLJSIMacros.h"
#include "JSIUtils/MGLJSIUtils.h"
#include "Utils/MGLUtils.h"
#else
#include "MGLJSIMacros.h"
#include "MGLJSIUtils.h"
#include "MGLUtils.h"
#endif

namespace margelo {

FieldDefinition GenerateSecretKeyFieldDefinition(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue) {
  return buildPair(
      "generateSecretKey", JSIF([=]) {
    auto skg = new SecretKeyGen();
    CHECK(skg->GetParamsFromJS(runtime, arguments));
    // make and return a promise
    auto promiseConstructor = runtime.global().getPropertyAsFunction(runtime, "Promise");
    auto promise = promiseConstructor.callAsConstructor(
        runtime,
        jsi::Function::createFromHostFunction(
            runtime,
            jsi::PropNameID::forAscii(runtime, "executor"),
            2,
            [&jsCallInvoker, skg](
                jsi::Runtime &runtime, const jsi::Value &,
                const jsi::Value *promiseArgs, size_t) -> jsi::Value {
              auto resolve = std::make_shared<jsi::Value>(runtime, promiseArgs[0]);
              auto reject = std::make_shared<jsi::Value>(runtime, promiseArgs[1]);
              try {
                jsCallInvoker->invokeAsync([&runtime, resolve, skg]() {
                  if (skg->DoKeyGen()) {
                    auto res = jsi::Object::createFromHostObject(runtime, skg->GetHandle());
                    resolve->asObject(runtime).asFunction(runtime).call(runtime, std::move(res));
                  } else {
                    throw std::runtime_error("Error generating key");
                  }
                });
              } catch (std::exception e) {
                jsCallInvoker->invokeAsync([&runtime, reject, e]() {
                  auto res = jsi::String::createFromUtf8(runtime, e.what());
                  reject->asObject(runtime).asFunction(runtime).call(runtime, std::move(res));
                });
              }
              return {};
            }
        )
    );
    return promise;
  });
};

bool SecretKeyGen::GetParamsFromJS(jsi::Runtime &rt, const jsi::Value *args) {
  SecretKeyGenConfig params;
  unsigned int offset = 0;

  // length
  CHECK(CheckIsUint32(args[offset]));
  uint32_t bits = (uint32_t)args[offset].asNumber();
  params.length = bits / CHAR_BIT;

  this->params_ = std::move(params);
  return true;
}

bool SecretKeyGen::DoKeyGen() {
  // TODO: threading / async here, as we don't have jsi::Runtime
  ByteSource::Builder bytes(this->params_.length);
  if (CSPRNG(bytes.data<unsigned char>(), this->params_.length).is_err())
    return false;
  auto key_data = std::move(bytes).release();
  this->key_ = KeyObjectData::CreateSecret(std::move(key_data));
  return true;
}

std::shared_ptr<KeyObjectHandle> SecretKeyGen::GetHandle() {
  auto handle = KeyObjectHandle::Create(this->key_);
  return handle;
}

} // namespace margelo
