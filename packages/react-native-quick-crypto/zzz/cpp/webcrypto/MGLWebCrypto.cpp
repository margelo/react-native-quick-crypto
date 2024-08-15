//
//  MGLWebCrypto.cpp
//  react-native-quick-crypto
//
//  Created by Oscar Franco on 1/12/23.
//

#include "MGLWebCrypto.h"

#include <memory>
#include <utility>
#include "MGLKeys.h"

#ifdef ANDROID
#include "JSIUtils/MGLJSIMacros.h"
#include "Sig/MGLSignHostObjects.h"
#include "Cipher/MGLRsa.h"
#include "Utils/MGLUtils.h"
#include "webcrypto/crypto_aes.h"
#include "webcrypto/crypto_ec.h"
#include "webcrypto/crypto_keygen.h"
#else
#include "MGLJSIMacros.h"
#include "MGLSignHostObjects.h"
#include "MGLRsa.h"
#include "MGLUtils.h"
#include "crypto_aes.h"
#include "crypto_ec.h"
#include "crypto_keygen.h"
#endif

namespace margelo {

namespace jsi = facebook::jsi;
namespace react = facebook::react;

MGLWebCryptoHostObject::MGLWebCryptoHostObject(
  std::shared_ptr<react::CallInvoker> jsCallInvoker,
  std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue)
  : MGLSmartHostObject(jsCallInvoker, workerQueue) {

  auto aesCipher = JSIF([=]) {
    auto aes = AESCipher();
    auto params = aes.GetParamsFromJS(runtime, arguments);
    ByteSource out;
    WebCryptoCipherStatus status = aes.DoCipher(params, &out);
    if (status != WebCryptoCipherStatus::OK) {
      throw jsi::JSError(runtime, "error in DoCipher, status: " +
        std::to_string(static_cast<int>(status)));
    }
    return toJSI(runtime, std::move(out));
  };

  auto createKeyObjectHandle = JSIF([=]) {
    auto keyObjectHandleHostObject = std::make_shared<KeyObjectHandle>();
    return jsi::Object::createFromHostObject(runtime, keyObjectHandleHostObject);
  };

  auto ecExportKey = JSIF([=]) {
    ByteSource out;
    std::shared_ptr<KeyObjectHandle> handle =
      std::static_pointer_cast<KeyObjectHandle>(
        arguments[1].asObject(runtime).getHostObject(runtime));
    std::shared_ptr<KeyObjectData> key_data = handle->Data();
    WebCryptoKeyExportStatus status = ECDH::doExport(runtime,
                                                     key_data,
                                                     static_cast<WebCryptoKeyFormat>(arguments[0].asNumber()),
                                                     {}, // blank params
                                                     &out);
    if (status != WebCryptoKeyExportStatus::OK) {
      throw jsi::JSError(runtime, "error exporting key, status: " + std::to_string(static_cast<int>(status)));
    }
    return toJSI(runtime, std::move(out));
  };

  auto generateSecretKeySync = JSIF([=]) {
    auto skg = new SecretKeyGen();
    CHECK(skg->GetParamsFromJS(runtime, arguments));
    CHECK(skg->DoKeyGen());
    auto out = jsi::Object::createFromHostObject(runtime, skg->GetHandle());
    return jsi::Value(std::move(out));
  };

  auto rsaCipher = JSIF([=]) {
    auto rsa = RSACipher();
    auto params = rsa.GetParamsFromJS(runtime, arguments);
    ByteSource out;
    WebCryptoCipherStatus status = rsa.DoCipher(params, &out);
    if (status != WebCryptoCipherStatus::OK) {
      throw jsi::JSError(runtime, "error in DoCipher, status: " +
        std::to_string(static_cast<int>(status)));
    }
    return toJSI(runtime, std::move(out));
  };

  auto rsaExportKey = JSIF([=]) {
    ByteSource out;
    auto rsa = new RsaKeyExport();
    CHECK(rsa->GetParamsFromJS(runtime, arguments));
    WebCryptoKeyExportStatus status = rsa->DoExport(&out);
    if (status != WebCryptoKeyExportStatus::OK) {
      throw jsi::JSError(runtime, "Error exporting key");
    }
    return toJSI(runtime, std::move(out));
  };

  auto signVerify = JSIF([=]) {
    auto ssv = SubtleSignVerify();
    auto params = ssv.GetParamsFromJS(runtime, arguments);
    ByteSource out;
    ssv.DoSignVerify(runtime, params, out);
    return ssv.EncodeOutput(runtime, params, out);
  };

  this->fields.push_back(buildPair("aesCipher", aesCipher));
  this->fields.push_back(buildPair("createKeyObjectHandle", createKeyObjectHandle));
  this->fields.push_back(buildPair("ecExportKey", ecExportKey));
  this->fields.push_back(GenerateSecretKeyFieldDefinition(jsCallInvoker, workerQueue));
  this->fields.push_back(buildPair("generateSecretKeySync", generateSecretKeySync));
  this->fields.push_back(buildPair("rsaCipher", rsaCipher));
  this->fields.push_back(buildPair("rsaExportKey", rsaExportKey));
  this->fields.push_back(buildPair("signVerify", signVerify));
};

}  // namespace margelo
