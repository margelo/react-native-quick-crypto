//
//  MGLPublicEncryptInstaller.cpp
//  react-native-fast-crypto
//
//  Created by Oscar on 17.06.22.
//

#include "MGLPublicEncryptInstaller.h"

#include <iostream>
#include <memory>

#include "MGLCipherKeys.h"

#ifdef ANDROID
#include "JSIUtils/MGLJSIMacros.h"
#else
#include "MGLJSIMacros.h"
#include "MGLJSIUtils.h"
#endif

using namespace facebook;

namespace margelo {

FieldDefinition getCreatePublicEncryptFieldDefinition(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue) {
  return HOST_LAMBDA("publicEncrypt", {
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
      std::cout << "Error: did not generate key!" << std::endl;
      return {};
    }

    auto buf = arguments[offset].asObject(runtime).getArrayBuffer(runtime);
    //    ArrayBufferOrViewContents<unsigned char> buf(args[offset]);
    if (!CheckSizeInt32(runtime, buf)) {
      jsi::detail::throwJSError(runtime, "Data buffer is too long");
      throw new jsi::JSError(runtime, "Data buffer is too long");
    }
    //      return THROW_ERR_OUT_OF_RANGE(env, "buffer is too long");

    uint32_t padding = static_cast<uint32_t>(arguments[offset + 1].getNumber());
    if (!padding) {
      return {};
    }
    //    if (!args[offset + 1]->Uint32Value(env->context()).To(&padding))
    //    return;

    const EVP_MD* digest = nullptr;
    if (arguments[offset + 2].isString()) {
      auto oaep_str = arguments[offset + 2].getString(runtime).utf8(runtime);

      digest = EVP_get_digestbyname(oaep_str.c_str());
      if (digest == nullptr) {
        jsi::detail::throwJSError(runtime, "Invalid digest (oaep_str)");
        throw new jsi::JSError(runtime, "Data buffer is too long (oaep_str)");
      }
      //        return THROW_ERR_OSSL_EVP_INVALID_DIGEST(env);
    }

    //    ArrayBufferOrViewContents<unsigned char> oaep_label;
    if (!arguments[offset + 3].isUndefined()) {
      //      auto oaep_label = ArrayBufferOrViewContents<unsigned
      //      char>(args[offset + 3]);
      auto oaep_label =
          arguments[offset + 3].getObject(runtime).getArrayBuffer(runtime);
      if (!CheckSizeInt32(runtime, oaep_label)) {
        jsi::detail::throwJSError(runtime, "oaep_label buffer is too long");
        throw new jsi::JSError(runtime, "oaep_label buffer is too long");
      }
    }

    std::cout << "Blah explosion!" << std::endl;

    //    std::unique_ptr<BackingStore> out;
    //    if (!Cipher<operation, EVP_PKEY_cipher_init, EVP_PKEY_cipher>(
    //                                                                  env,
    //                                                                  pkey,
    //                                                                  padding,
    //                                                                  digest,
    //                                                                  oaep_label,
    //                                                                  buf,
    //                                                                  &out)) {
    //                                                                    return
    //                                                                    ThrowCryptoError(env,
    //                                                                    ERR_get_error());
    //                                                                  }

    //    Local<ArrayBuffer> ab = ArrayBuffer::New(env->isolate(),
    //    std::move(out)); args.GetReturnValue().Set(
    //                              Buffer::New(env, ab, 0,
    //                              ab->ByteLength()).FromMaybe(Local<Value>()));

    return {};
  });
}
}  // namespace margelo
