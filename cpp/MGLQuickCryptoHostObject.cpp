// Copyright 2022 Margelo
#include "MGLQuickCryptoHostObject.h"

#include <ReactCommon/TurboModuleUtils.h>
#include <jsi/jsi.h>

#include <memory>
#include <string>
#include <vector>

#ifdef ANDROID
#include "Cipher/MGLCreateCipherInstaller.h"
#include "Cipher/MGLCreateDecipherInstaller.h"
#include "Cipher/MGLGenerateKeyPairInstaller.h"
#include "Cipher/MGLGenerateKeyPairSyncInstaller.h"
#include "Cipher/MGLPublicCipher.h"
#include "Cipher/MGLPublicCipherInstaller.h"
#include "HMAC/MGLHmacInstaller.h"
#include "Hash/MGLHashInstaller.h"
#include "Random/MGLRandomHostObject.h"
#include "Sig/MGLSignInstaller.h"
#include "Sig/MGLVerifyInstaller.h"
#include "fastpbkdf2/MGLPbkdf2HostObject.h"
#include "webcrypto/MGLWebCrypto.h"
#else
#include "MGLCreateCipherInstaller.h"
#include "MGLCreateDecipherInstaller.h"
#include "MGLGenerateKeyPairInstaller.h"
#include "MGLGenerateKeyPairSyncInstaller.h"
#include "MGLHashInstaller.h"
#include "MGLHmacInstaller.h"
#include "MGLPbkdf2HostObject.h"
#include "MGLPublicCipher.h"
#include "MGLPublicCipherInstaller.h"
#include "MGLRandomHostObject.h"
#include "MGLSignInstaller.h"
#include "MGLVerifyInstaller.h"
#include "MGLWebCrypto.h"
#endif

namespace margelo {

namespace jsi = facebook::jsi;

MGLQuickCryptoHostObject::MGLQuickCryptoHostObject(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue)
    : MGLSmartHostObject(jsCallInvoker, workerQueue) {
  // HmacInstaller
  this->fields.push_back(getHmacFieldDefinition(jsCallInvoker, workerQueue));

  // HashInstaller
  this->fields.push_back(getHashFieldDefinition(jsCallInvoker, workerQueue));

  // createCipher
  this->fields.push_back(
      getCreateCipherFieldDefinition(jsCallInvoker, workerQueue));

  // createDecipher
  this->fields.push_back(
      getCreateDecipherFieldDefinition(jsCallInvoker, workerQueue));

  // publicEncrypt
  this->fields.push_back(
      getPublicCipherFieldDefinition<MGLPublicCipher::kPublic,
                                     EVP_PKEY_encrypt_init, EVP_PKEY_encrypt>(
          "publicEncrypt", jsCallInvoker, workerQueue));

  // privateDecrypt
  this->fields.push_back(
      getPublicCipherFieldDefinition<MGLPublicCipher::kPrivate,
                                     EVP_PKEY_decrypt_init, EVP_PKEY_decrypt>(
          "privateDecrypt", jsCallInvoker, workerQueue));

  // privateEncrypt
  this->fields.push_back(
      getPublicCipherFieldDefinition<MGLPublicCipher::kPrivate,
                                     EVP_PKEY_sign_init, EVP_PKEY_sign>(
          "privateEncrypt", jsCallInvoker, workerQueue));

  // publicDecrypt
  this->fields.push_back(
      getPublicCipherFieldDefinition<MGLPublicCipher::kPublic,
                                     EVP_PKEY_verify_recover_init,
                                     EVP_PKEY_verify_recover>(
          "publicDecrypt", jsCallInvoker, workerQueue));

  // generateKeyPair
  this->fields.push_back(
      getGenerateKeyPairFieldDefinition(jsCallInvoker, workerQueue));

  // generateKeyPairSync
  this->fields.push_back(
      getGenerateKeyPairSyncFieldDefinition(jsCallInvoker, workerQueue));

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

  // subtle API created from a simple jsi::Object
  // because this FieldDefinition is only good for returning
  // objects and too convoluted
    this->fields.push_back(JSI_VALUE("webcrypto", {
      return createWebCryptoObject(runtime);
    }));
}

}  // namespace margelo
