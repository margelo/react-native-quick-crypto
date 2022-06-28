//
//  MGLPublicCipher.h
//  react-native-fast-crypto
//
//  Created by Oscar on 17.06.22.
//

#ifndef MGLPublicCipher_h
#define MGLPublicCipher_h

#include <jsi/jsi.h>
#include <openssl/evp.h>

#include <optional>
#include <vector>

#include "MGLCipherKeys.h"
#ifdef ANDROID
#include "JSIUtils/MGLJSIUtils.h"
#include "JSIUtils/MGLTypedArray.h"
#else
#include "MGLJSIUtils.h"
#include "MGLTypedArray.h"
#endif

namespace margelo {

namespace jsi = facebook::jsi;

class MGLPublicCipher {
 public:
  typedef int (*EVP_PKEY_cipher_init_t)(EVP_PKEY_CTX* ctx);
  typedef int (*EVP_PKEY_cipher_t)(EVP_PKEY_CTX* ctx, unsigned char* out,
                                   size_t* outlen, const unsigned char* in,
                                   size_t inlen);

  enum Operation { kPublic, kPrivate };

  template <Operation operation, EVP_PKEY_cipher_init_t EVP_PKEY_cipher_init,
            EVP_PKEY_cipher_t EVP_PKEY_cipher>
  static std::optional<jsi::Value> Cipher(jsi::Runtime& runtime,
                                          const ManagedEVPPKey& pkey,
                                          int padding, const EVP_MD* digest,
                                          const jsi::Value& oaep_label,
                                          jsi::ArrayBuffer& data);
};

template <MGLPublicCipher::Operation operation,
          MGLPublicCipher::EVP_PKEY_cipher_init_t EVP_PKEY_cipher_init,
          MGLPublicCipher::EVP_PKEY_cipher_t EVP_PKEY_cipher>
std::optional<jsi::Value> MGLPublicCipher::Cipher(jsi::Runtime& runtime,
                                                  const ManagedEVPPKey& pkey,
                                                  int padding,
                                                  const EVP_MD* digest,
                                                  const jsi::Value& oaep_label,
                                                  jsi::ArrayBuffer& data) {
  EVPKeyCtxPointer ctx(EVP_PKEY_CTX_new(pkey.get(), nullptr));

  if (!ctx) {
    return {};
  }

  if (EVP_PKEY_cipher_init(ctx.get()) <= 0) {
    return {};
  }

  if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), padding) <= 0) {
    return {};
  }

  if (digest != nullptr) {
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), digest) <= 0) {
      return {};
    }
  }

  if (!oaep_label.isUndefined()) {
    auto oaep_label_buffer =
        oaep_label.asObject(runtime).getArrayBuffer(runtime);
    // OpenSSL takes ownership of the label, so we need to create a copy.
    void* label = OPENSSL_memdup(oaep_label_buffer.data(runtime),
                                 oaep_label_buffer.size(runtime));
    if (label == nullptr) {
      throw new jsi::JSError(runtime, "Error openSSL memdump oaep label");
    }

    if (0 >= EVP_PKEY_CTX_set0_rsa_oaep_label(
                 ctx.get(), static_cast<unsigned char*>(label),
                 static_cast<int>(oaep_label_buffer.size(runtime)))) {
      OPENSSL_free(label);
      return {};
    }
  }

  // First pass without storing to get the out_len
  size_t out_len = 0;
  if (EVP_PKEY_cipher(ctx.get(), nullptr, &out_len, data.data(runtime),
                      data.size(runtime)) <= 0) {
    return {};
  }

  std::vector<unsigned char> out_vec(out_len);

  if (EVP_PKEY_cipher(ctx.get(), out_vec.data(), &out_len, data.data(runtime),
                      data.size(runtime)) <= 0) {
    return {};
  }

  MGLTypedArray<MGLTypedArrayKind::Uint8Array> outBuffer(runtime, out_len);

  outBuffer.update(runtime, out_vec);

  return outBuffer.getArrayBuffer(runtime);
}

}  // namespace margelo

#endif /* MGLPublicCipher_h */
