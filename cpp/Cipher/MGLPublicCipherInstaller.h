//
//  MGLPrivateDecryptInstaller.h
//  react-native-quick-crypto
//
//  Created by Oscar on 28.06.22.
//

#ifndef MGLPublicCipherInstaller_h
#define MGLPublicCipherInstaller_h

#include <jsi/jsi.h>
#include <openssl/evp.h>

#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "MGLCipherKeys.h"
#include "MGLPublicCipher.h"

#ifdef ANDROID
#include "JSIUtils/MGLJSIUtils.h"
#include "JSIUtils/MGLSmartHostObject.h"
#include "JSIUtils/MGLTypedArray.h"
#else
#include "MGLJSIUtils.h"
#include "MGLSmartHostObject.h"
#include "MGLTypedArray.h"
#endif

namespace margelo {
namespace jsi = facebook::jsi;

// "publicEncrypt", "publicDecrypt", "privateEncrypt", "privateDecrypt" all use
// the same key extraction logic, only vary in the final openSSL call, so this
// is a template that accepts and incoming template function, think of it as a
// weird lambda before real lambdas Because this is a template, the
// implementation needs to be in this header to prevent linker failure
template <MGLPublicCipher::Operation operation,
          MGLPublicCipher::EVP_PKEY_cipher_init_t EVP_PKEY_cipher_init,
          MGLPublicCipher::EVP_PKEY_cipher_t EVP_PKEY_cipher>
FieldDefinition getPublicCipherFieldDefinition(
    std::string name, std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue) {
  return buildPair(
      name, JSIF([=]) {
        // there is a variable amount of parameters passed depending on the
        // scheme therefore making param validation on this level makes little
        // sense everything should be done on JS, which makes this a bit unsafe
        // but it's acceptable
        unsigned int offset = 0;

        ManagedEVPPKey pkey = ManagedEVPPKey::GetPublicOrPrivateKeyFromJs(
            runtime, arguments, &offset);

        if (!pkey) {
          jsi::detail::throwJSError(runtime, "Could not generate key");
          throw new jsi::JSError(runtime, "Could not generate key");
        }

        auto buf = arguments[offset].asObject(runtime).getArrayBuffer(runtime);
        if (!CheckSizeInt32(runtime, buf)) {
          jsi::detail::throwJSError(runtime, "Data buffer is too long");
          throw new jsi::JSError(runtime, "Data buffer is too long");
        }

        uint32_t padding =
            static_cast<uint32_t>(arguments[offset + 1].getNumber());
        if (!padding) {
          jsi::detail::throwJSError(runtime, "Invalid padding");
          throw new jsi::JSError(runtime, "Invalid padding");
        }

        const EVP_MD* digest = nullptr;
        if (arguments[offset + 2].isString()) {
          auto oaep_str =
              arguments[offset + 2].getString(runtime).utf8(runtime);

          digest = EVP_get_digestbyname(oaep_str.c_str());
          if (digest == nullptr) {
            jsi::detail::throwJSError(runtime, "Invalid digest (oaep_str)");
            throw new jsi::JSError(runtime, "Invalid digest (oaep_str)");
          }
        }

        if (!arguments[offset + 3].isUndefined()) {
          auto oaep_label_buffer =
              arguments[offset + 3].getObject(runtime).getArrayBuffer(runtime);
          if (!CheckSizeInt32(runtime, oaep_label_buffer)) {
            jsi::detail::throwJSError(runtime, "oaep_label buffer is too long");
            throw new jsi::JSError(runtime, "oaep_label buffer is too long");
          }
        }

        std::optional<jsi::Value> out =
            MGLPublicCipher::Cipher<operation, EVP_PKEY_cipher_init,
                                    EVP_PKEY_cipher>(
                runtime, pkey, padding, digest, arguments[offset + 3], buf);

        if (!out.has_value()) {
          jsi::detail::throwJSError(runtime, "Failed to decrypt");
          throw new jsi::JSError(runtime, "Failed to decrypt");
        }

        return out.value().getObject(runtime);
      });
}
}  // namespace margelo

#endif /* MGLPublicCipherInstaller_h */
