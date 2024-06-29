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

  jsi::Value SecretKeyGen::DoKeyGen(jsi::Runtime &rt, const jsi::Value *args) {
    auto skg = new SecretKeyGen(FnMode::kAsync);
    CHECK(skg->getParamsFromJS(rt, args));
    CHECK(skg->doKeyGen());
    auto out = jsi::Object::createFromHostObject(rt, skg->getHandle());
    return jsi::Value(std::move(out));
  }

  jsi::Value SecretKeyGen::DoKeyGenSync(jsi::Runtime &rt, const jsi::Value *args) {
    auto skg = new SecretKeyGen(FnMode::kSync);
    CHECK(skg->getParamsFromJS(rt, args));
    CHECK(skg->doKeyGen());
    auto out = jsi::Object::createFromHostObject(rt, skg->getHandle());
    return jsi::Value(std::move(out));
  }

  bool SecretKeyGen::getParamsFromJS(jsi::Runtime &rt, const jsi::Value *args) {
    SecretKeyGenConfig params;
    unsigned int offset = 0;

    // length
    CHECK(CheckIsUint32(args[offset]));
    uint32_t bits = (uint32_t)args[offset].asNumber();
    params.length = bits / CHAR_BIT;

    this->params_ = std::move(params);
    return true;
  }

  bool SecretKeyGen::doKeyGen() {
    // TODO: threading / async here, as we don't have jsi::Runtime
    ByteSource::Builder bytes(this->params_.length);
    if (CSPRNG(bytes.data<unsigned char>(), this->params_.length).is_err())
      return false;
    auto key_data = std::move(bytes).release();
    this->key_ = KeyObjectData::CreateSecret(std::move(key_data));
    return true;
  }

  std::shared_ptr<KeyObjectHandle> SecretKeyGen::getHandle() {
    auto handle = KeyObjectHandle::Create(this->key_);
    return handle;
  }

} // namespace margelo
