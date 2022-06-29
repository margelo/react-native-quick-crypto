//
//  MGLPublicEncryptInstaller.cpp
//  react-native-fast-crypto
//
//  Created by Oscar on 17.06.22.
//

#include "MGLPrivateDecryptInstaller.h"

#include <iostream>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include "MGLCipherKeys.h"
#include "MGLPublicCipher.h"

#ifdef ANDROID
#include "JSIUtils/MGLJSIUtils.h"
#include "JSIUtils/MGLTypedArray.h"
#else
#include "MGLJSIUtils.h"
#include "MGLTypedArray.h"
#include "logs.h"
#endif

namespace margelo {

namespace jsi = facebook::jsi;

FieldDefinition getPrivateDecryptFieldDefinition(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue) {
  return buildPair(
      "privateDecrypt", JSIF([=]) {
        // TODO(osp) validation of params
        //    if (count < 1) {
        //      throw jsi::JSError(runtime, "Params object is required");
        //    }
        //
        //    if (!arguments[0].isObject()) {
        //      throw jsi::JSError(runtime, "createCipher: Params needs to be an
        //      object");
        //    }
        //
        //    auto params = arguments[0].getObject(runtime);

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
            MGLPublicCipher::Cipher<MGLPublicCipher::kPrivate,
                                    EVP_PKEY_decrypt_init, EVP_PKEY_decrypt>(
                runtime, pkey, padding, digest, arguments[offset + 3], buf);

        if (!out.has_value()) {
          jsi::detail::throwJSError(runtime, "Failed to encrypt");
          throw new jsi::JSError(runtime, "Failed to encrypt");
        }

        return out.value().getObject(runtime);
      });
}
}  // namespace margelo
