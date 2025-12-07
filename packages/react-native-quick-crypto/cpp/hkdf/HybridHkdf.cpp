#include <NitroModules/ArrayBuffer.hpp>
#include <memory>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <string>
#include <vector>

#include "HybridHkdf.hpp"
#include "Utils.hpp"

namespace margelo::nitro::crypto {

std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>> HybridHkdf::hkdf(const std::string& algorithm,
                                                                        const std::shared_ptr<ArrayBuffer>& key,
                                                                        const std::shared_ptr<ArrayBuffer>& salt,
                                                                        const std::shared_ptr<ArrayBuffer>& info, double length) {
  // get owned NativeArrayBuffers before passing to sync function
  auto nativeKey = ToNativeArrayBuffer(key);
  auto nativeSalt = ToNativeArrayBuffer(salt);
  auto nativeInfo = ToNativeArrayBuffer(info);

  return Promise<std::shared_ptr<ArrayBuffer>>::async([this, algorithm, nativeKey, nativeSalt, nativeInfo, length]() {
    return this->deriveKey(algorithm, nativeKey, nativeSalt, nativeInfo, length);
  });
}

std::shared_ptr<ArrayBuffer> HybridHkdf::deriveKey(const std::string& algorithm, const std::shared_ptr<ArrayBuffer>& baseKey,
                                                   const std::shared_ptr<ArrayBuffer>& salt, const std::shared_ptr<ArrayBuffer>& info,
                                                   double length) {
  EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
  if (kdf == nullptr) {
    throw std::runtime_error("Failed to fetch HKDF implementation: " + std::to_string(ERR_get_error()));
  }

  EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);
  EVP_KDF_free(kdf);
  if (ctx == nullptr) {
    throw std::runtime_error("Failed to create HKDF context: " + std::to_string(ERR_get_error()));
  }

  // Set up parameters
  OSSL_PARAM params[5];
  size_t paramIndex = 0;

  params[paramIndex++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char*>(algorithm.c_str()), 0);

  // Key (Input Keying Material)
  if (baseKey && baseKey->size() > 0) {
    params[paramIndex++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, baseKey->data(), baseKey->size());
  } else {
    // Empty key is allowed in HKDF (defaults to zero string of hashLen) but explicit param usually expected if not null
    // If we want empty, we can pass generic empty buffer or handle it.
    // Node.js crypto allows buffer.
    // Assuming key is effectively required or can be empty.
    params[paramIndex++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, nullptr, 0);
  }

  // Salt
  if (salt && salt->size() > 0) {
    params[paramIndex++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt->data(), salt->size());
  } else {
    // If salt is not provided, it is set to a string of HashLen zeros.
    // OpenSSL handles missing salt as default? Or do we need to pass empty?
    // Usually standard optional.
  }

  // Info
  if (info && info->size() > 0) {
    params[paramIndex++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info->data(), info->size());
  }

  params[paramIndex++] = OSSL_PARAM_construct_end();

  // Output buffer
  size_t outLen = static_cast<size_t>(length);
  if (outLen == 0) {
    EVP_KDF_CTX_free(ctx);
    throw std::runtime_error("HKDF length cannot be zero");
  }

  uint8_t* outBuf = new uint8_t[outLen];

  if (EVP_KDF_derive(ctx, outBuf, outLen, params) <= 0) {
    EVP_KDF_CTX_free(ctx);
    delete[] outBuf;
    throw std::runtime_error("HKDF derivation failed: " + std::to_string(ERR_get_error()));
  }

  EVP_KDF_CTX_free(ctx);

  return std::make_shared<NativeArrayBuffer>(outBuf, outLen, [=]() { delete[] outBuf; });
}

} // namespace margelo::nitro::crypto
