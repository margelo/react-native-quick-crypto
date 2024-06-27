#include "crypto_keygen.h"

#ifdef ANDROID
#include "JSIUtils/MGLJSIMacros.h"
#include "Utils/MGLUtils.h"
#else
#include "MGLJSIUtils.h"
#include "MGLUtils.h"
#endif

namespace margelo {

  jsi::Value SecretKeyGen::DoKeyGen(jsi::Runtime &rt, const jsi::Value *args) {
    auto skg = new SecretKeyGen(FnMode::kAsync);
    CHECK(skg->getParamsFromJS(rt, args));
    CHECK(skg->doKeyGen());
    return toJSI(rt, std::move(skg->getKey()));
  }

  jsi::Value SecretKeyGen::DoKeyGenSync(jsi::Runtime &rt, const jsi::Value *args) {
    auto skg = new SecretKeyGen(FnMode::kSync);
    CHECK(skg->getParamsFromJS(rt, args));
    CHECK(skg->doKeyGen());
    return toJSI(rt, std::move(skg->getKey()));
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
    this->key_ = std::move(bytes).release();
    return true;
  }

  ByteSource SecretKeyGen::getKey() {
    return std::move(this->key_);
  }

} // namespace margelo
