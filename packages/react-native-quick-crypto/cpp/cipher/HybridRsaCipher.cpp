#include "HybridRsaCipher.hpp"
#include "Utils.hpp"
#include "../keys/HybridKeyObjectHandle.hpp"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <cstring>

namespace margelo::nitro::crypto {

using margelo::nitro::NativeArrayBuffer;

// Helper to get OpenSSL digest from hash algorithm name
const EVP_MD* getDigestByName(const std::string& hashAlgorithm) {
  if (hashAlgorithm == "SHA-1" || hashAlgorithm == "SHA1" || hashAlgorithm == "sha1" || hashAlgorithm == "sha-1") {
    return EVP_sha1();
  } else if (hashAlgorithm == "SHA-256" || hashAlgorithm == "SHA256" || hashAlgorithm == "sha256" || hashAlgorithm == "sha-256") {
    return EVP_sha256();
  } else if (hashAlgorithm == "SHA-384" || hashAlgorithm == "SHA384" || hashAlgorithm == "sha384" || hashAlgorithm == "sha-384") {
    return EVP_sha384();
  } else if (hashAlgorithm == "SHA-512" || hashAlgorithm == "SHA512" || hashAlgorithm == "sha512" || hashAlgorithm == "sha-512") {
    return EVP_sha512();
  }
  throw std::runtime_error("Unsupported hash algorithm: " + hashAlgorithm);
}

std::shared_ptr<ArrayBuffer> HybridRsaCipher::encrypt(const std::shared_ptr<HybridKeyObjectHandleSpec>& keyHandle,
                                                       const std::shared_ptr<ArrayBuffer>& data,
                                                       const std::string& hashAlgorithm,
                                                       const std::optional<std::shared_ptr<ArrayBuffer>>& label) {
  // Get the EVP_PKEY from the key handle
  auto keyHandleImpl = std::static_pointer_cast<HybridKeyObjectHandle>(keyHandle);
  EVP_PKEY* pkey = keyHandleImpl->getKeyObjectData().GetAsymmetricKey().get();
  
  if (!pkey) {
    throw std::runtime_error("Invalid key for RSA encryption");
  }

  // Create context for encryption
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
  if (!ctx) {
    throw std::runtime_error("Failed to create EVP_PKEY_CTX");
  }

  // Initialize encryption
  if (EVP_PKEY_encrypt_init(ctx) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error("Failed to initialize encryption: " + std::string(err_buf));
  }

  // Set padding to OAEP
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("Failed to set RSA OAEP padding");
  }

  // Set OAEP hash algorithm
  const EVP_MD* md = getDigestByName(hashAlgorithm);
  if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("Failed to set OAEP hash algorithm");
  }

  // Set MGF1 hash (same as OAEP hash per WebCrypto spec)
  if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("Failed to set MGF1 hash algorithm");
  }

  // Set OAEP label if provided
  if (label.has_value() && label.value()->size() > 0) {
    auto native_label = ToNativeArrayBuffer(label.value());
    // OpenSSL takes ownership of the label, so we need to allocate a copy
    unsigned char* label_copy = (unsigned char*)OPENSSL_malloc(native_label->size());
    if (!label_copy) {
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("Failed to allocate memory for label");
    }
    std::memcpy(label_copy, native_label->data(), native_label->size());
    
    if (EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, label_copy, native_label->size()) <= 0) {
      OPENSSL_free(label_copy);
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("Failed to set OAEP label");
    }
  }

  // Get input data
  auto native_data = ToNativeArrayBuffer(data);
  const unsigned char* in = native_data->data();
  size_t inlen = native_data->size();

  // Determine output length
  size_t outlen;
  if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, in, inlen) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error("Failed to determine output length: " + std::string(err_buf));
  }

  // Allocate output buffer
  auto out_buf = std::make_unique<uint8_t[]>(outlen);

  // Perform encryption
  if (EVP_PKEY_encrypt(ctx, out_buf.get(), &outlen, in, inlen) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error("Encryption failed: " + std::string(err_buf));
  }

  EVP_PKEY_CTX_free(ctx);

  // Create ArrayBuffer from result
  uint8_t* raw_ptr = out_buf.get();
  return std::make_shared<NativeArrayBuffer>(out_buf.release(), outlen, [raw_ptr]() { delete[] raw_ptr; });
}

std::shared_ptr<ArrayBuffer> HybridRsaCipher::decrypt(const std::shared_ptr<HybridKeyObjectHandleSpec>& keyHandle,
                                                       const std::shared_ptr<ArrayBuffer>& data,
                                                       const std::string& hashAlgorithm,
                                                       const std::optional<std::shared_ptr<ArrayBuffer>>& label) {
  // Get the EVP_PKEY from the key handle
  auto keyHandleImpl = std::static_pointer_cast<HybridKeyObjectHandle>(keyHandle);
  EVP_PKEY* pkey = keyHandleImpl->getKeyObjectData().GetAsymmetricKey().get();
  
  if (!pkey) {
    throw std::runtime_error("Invalid key for RSA decryption");
  }

  // Create context for decryption
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
  if (!ctx) {
    throw std::runtime_error("Failed to create EVP_PKEY_CTX");
  }

  // Initialize decryption
  if (EVP_PKEY_decrypt_init(ctx) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error("Failed to initialize decryption: " + std::string(err_buf));
  }

  // Set padding to OAEP
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("Failed to set RSA OAEP padding");
  }

  // Set OAEP hash algorithm
  const EVP_MD* md = getDigestByName(hashAlgorithm);
  if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("Failed to set OAEP hash algorithm");
  }

  // Set MGF1 hash (same as OAEP hash per WebCrypto spec)
  if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("Failed to set MGF1 hash algorithm");
  }

  // Set OAEP label if provided
  if (label.has_value() && label.value()->size() > 0) {
    auto native_label = ToNativeArrayBuffer(label.value());
    // OpenSSL takes ownership of the label, so we need to allocate a copy
    unsigned char* label_copy = (unsigned char*)OPENSSL_malloc(native_label->size());
    if (!label_copy) {
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("Failed to allocate memory for label");
    }
    std::memcpy(label_copy, native_label->data(), native_label->size());
    
    if (EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, label_copy, native_label->size()) <= 0) {
      OPENSSL_free(label_copy);
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("Failed to set OAEP label");
    }
  }

  // Get input data
  auto native_data = ToNativeArrayBuffer(data);
  const unsigned char* in = native_data->data();
  size_t inlen = native_data->size();

  // Determine output length
  size_t outlen;
  if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, in, inlen) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error("Failed to determine output length: " + std::string(err_buf));
  }

  // Allocate output buffer
  auto out_buf = std::make_unique<uint8_t[]>(outlen);

  // Perform decryption
  if (EVP_PKEY_decrypt(ctx, out_buf.get(), &outlen, in, inlen) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error("Decryption failed: " + std::string(err_buf));
  }

  EVP_PKEY_CTX_free(ctx);

  // Create ArrayBuffer from result
  uint8_t* raw_ptr = out_buf.get();
  return std::make_shared<NativeArrayBuffer>(out_buf.release(), outlen, [raw_ptr]() { delete[] raw_ptr; });
}

void HybridRsaCipher::loadHybridMethods() {
  registerHybrids(this, [](Prototype& prototype) {
    prototype.registerHybridMethod("encrypt", &HybridRsaCipher::encrypt);
    prototype.registerHybridMethod("decrypt", &HybridRsaCipher::decrypt);
  });
}

} // namespace margelo::nitro::crypto
