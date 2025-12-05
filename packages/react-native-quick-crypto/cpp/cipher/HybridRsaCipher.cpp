#include "HybridRsaCipher.hpp"
#include "../keys/HybridKeyObjectHandle.hpp"
#include "Utils.hpp"

#include <cstring>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

namespace margelo::nitro::crypto {

using margelo::nitro::NativeArrayBuffer;

constexpr int kRsaPkcs1Padding = 1;
constexpr int kRsaOaepPadding = 4;

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

int toOpenSSLPadding(int padding) {
  switch (padding) {
    case kRsaPkcs1Padding:
      return RSA_PKCS1_PADDING;
    case kRsaOaepPadding:
      return RSA_PKCS1_OAEP_PADDING;
    default:
      throw std::runtime_error("Unsupported padding mode: " + std::to_string(padding));
  }
}

std::shared_ptr<ArrayBuffer> HybridRsaCipher::encrypt(const std::shared_ptr<HybridKeyObjectHandleSpec>& keyHandle,
                                                      const std::shared_ptr<ArrayBuffer>& data, double padding,
                                                      const std::string& hashAlgorithm,
                                                      const std::optional<std::shared_ptr<ArrayBuffer>>& label) {
  auto keyHandleImpl = std::static_pointer_cast<HybridKeyObjectHandle>(keyHandle);
  EVP_PKEY* pkey = keyHandleImpl->getKeyObjectData().GetAsymmetricKey().get();

  if (!pkey) {
    throw std::runtime_error("Invalid key for RSA encryption");
  }

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
  if (!ctx) {
    throw std::runtime_error("Failed to create EVP_PKEY_CTX");
  }

  if (EVP_PKEY_encrypt_init(ctx) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error("Failed to initialize encryption: " + std::string(err_buf));
  }

  int paddingInt = static_cast<int>(padding);
  int opensslPadding = toOpenSSLPadding(paddingInt);

  if (EVP_PKEY_CTX_set_rsa_padding(ctx, opensslPadding) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("Failed to set RSA padding");
  }

  if (paddingInt == kRsaOaepPadding) {
    const EVP_MD* md = getDigestByName(hashAlgorithm);
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0) {
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("Failed to set OAEP hash algorithm");
    }

    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) <= 0) {
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("Failed to set MGF1 hash algorithm");
    }

    if (label.has_value() && label.value()->size() > 0) {
      auto native_label = ToNativeArrayBuffer(label.value());
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
  }

  auto native_data = ToNativeArrayBuffer(data);
  const unsigned char* in = native_data->data();
  size_t inlen = native_data->size();

  size_t outlen;
  if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, in, inlen) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error("Failed to determine output length: " + std::string(err_buf));
  }

  auto out_buf = std::make_unique<uint8_t[]>(outlen);

  if (EVP_PKEY_encrypt(ctx, out_buf.get(), &outlen, in, inlen) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error("Encryption failed: " + std::string(err_buf));
  }

  EVP_PKEY_CTX_free(ctx);

  uint8_t* raw_ptr = out_buf.get();
  return std::make_shared<NativeArrayBuffer>(out_buf.release(), outlen, [raw_ptr]() { delete[] raw_ptr; });
}

std::shared_ptr<ArrayBuffer> HybridRsaCipher::decrypt(const std::shared_ptr<HybridKeyObjectHandleSpec>& keyHandle,
                                                      const std::shared_ptr<ArrayBuffer>& data, double padding,
                                                      const std::string& hashAlgorithm,
                                                      const std::optional<std::shared_ptr<ArrayBuffer>>& label) {
  auto keyHandleImpl = std::static_pointer_cast<HybridKeyObjectHandle>(keyHandle);
  EVP_PKEY* pkey = keyHandleImpl->getKeyObjectData().GetAsymmetricKey().get();

  if (!pkey) {
    throw std::runtime_error("Invalid key for RSA decryption");
  }

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
  if (!ctx) {
    throw std::runtime_error("Failed to create EVP_PKEY_CTX");
  }

  if (EVP_PKEY_decrypt_init(ctx) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error("Failed to initialize decryption: " + std::string(err_buf));
  }

  int paddingInt = static_cast<int>(padding);
  int opensslPadding = toOpenSSLPadding(paddingInt);

  if (EVP_PKEY_CTX_set_rsa_padding(ctx, opensslPadding) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("Failed to set RSA padding");
  }

  if (paddingInt == kRsaOaepPadding) {
    const EVP_MD* md = getDigestByName(hashAlgorithm);
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0) {
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("Failed to set OAEP hash algorithm");
    }

    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) <= 0) {
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("Failed to set MGF1 hash algorithm");
    }

    if (label.has_value() && label.value()->size() > 0) {
      auto native_label = ToNativeArrayBuffer(label.value());
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
  }

  auto native_data = ToNativeArrayBuffer(data);
  const unsigned char* in = native_data->data();
  size_t inlen = native_data->size();

  size_t outlen;
  if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, in, inlen) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error("Failed to determine output length: " + std::string(err_buf));
  }

  auto out_buf = std::make_unique<uint8_t[]>(outlen);

  if (EVP_PKEY_decrypt(ctx, out_buf.get(), &outlen, in, inlen) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error("Decryption failed: " + std::string(err_buf));
  }

  EVP_PKEY_CTX_free(ctx);

  uint8_t* raw_ptr = out_buf.get();
  return std::make_shared<NativeArrayBuffer>(out_buf.release(), outlen, [raw_ptr]() { delete[] raw_ptr; });
}

std::shared_ptr<ArrayBuffer> HybridRsaCipher::privateEncrypt(const std::shared_ptr<HybridKeyObjectHandleSpec>& keyHandle,
                                                             const std::shared_ptr<ArrayBuffer>& data, double padding) {
  auto keyHandleImpl = std::static_pointer_cast<HybridKeyObjectHandle>(keyHandle);
  EVP_PKEY* pkey = keyHandleImpl->getKeyObjectData().GetAsymmetricKey().get();

  if (!pkey) {
    throw std::runtime_error("Invalid key for RSA private encryption");
  }

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
  if (!ctx) {
    throw std::runtime_error("Failed to create EVP_PKEY_CTX");
  }

  if (EVP_PKEY_sign_init(ctx) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error("Failed to initialize signing: " + std::string(err_buf));
  }

  int paddingInt = static_cast<int>(padding);
  int opensslPadding = toOpenSSLPadding(paddingInt);

  if (EVP_PKEY_CTX_set_rsa_padding(ctx, opensslPadding) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("Failed to set RSA padding");
  }

  auto native_data = ToNativeArrayBuffer(data);
  const unsigned char* in = native_data->data();
  size_t inlen = native_data->size();

  size_t outlen;
  if (EVP_PKEY_sign(ctx, nullptr, &outlen, in, inlen) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error("Failed to determine output length: " + std::string(err_buf));
  }

  auto out_buf = std::make_unique<uint8_t[]>(outlen);

  if (EVP_PKEY_sign(ctx, out_buf.get(), &outlen, in, inlen) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error("Private encryption failed: " + std::string(err_buf));
  }

  EVP_PKEY_CTX_free(ctx);

  uint8_t* raw_ptr = out_buf.get();
  return std::make_shared<NativeArrayBuffer>(out_buf.release(), outlen, [raw_ptr]() { delete[] raw_ptr; });
}

std::shared_ptr<ArrayBuffer> HybridRsaCipher::privateDecrypt(const std::shared_ptr<HybridKeyObjectHandleSpec>& keyHandle,
                                                             const std::shared_ptr<ArrayBuffer>& data, double padding) {
  auto keyHandleImpl = std::static_pointer_cast<HybridKeyObjectHandle>(keyHandle);
  EVP_PKEY* pkey = keyHandleImpl->getKeyObjectData().GetAsymmetricKey().get();

  if (!pkey) {
    throw std::runtime_error("Invalid key for RSA private decryption");
  }

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
  if (!ctx) {
    throw std::runtime_error("Failed to create EVP_PKEY_CTX");
  }

  if (EVP_PKEY_verify_recover_init(ctx) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error("Failed to initialize verify recover: " + std::string(err_buf));
  }

  int paddingInt = static_cast<int>(padding);
  int opensslPadding = toOpenSSLPadding(paddingInt);

  if (EVP_PKEY_CTX_set_rsa_padding(ctx, opensslPadding) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("Failed to set RSA padding");
  }

  auto native_data = ToNativeArrayBuffer(data);
  const unsigned char* in = native_data->data();
  size_t inlen = native_data->size();

  size_t outlen;
  if (EVP_PKEY_verify_recover(ctx, nullptr, &outlen, in, inlen) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error("Failed to determine output length: " + std::string(err_buf));
  }

  if (outlen == 0) {
    EVP_PKEY_CTX_free(ctx);
    uint8_t* empty_buf = new uint8_t[1];
    return std::make_shared<NativeArrayBuffer>(empty_buf, 0, [empty_buf]() { delete[] empty_buf; });
  }

  auto out_buf = std::make_unique<uint8_t[]>(outlen);

  if (EVP_PKEY_verify_recover(ctx, out_buf.get(), &outlen, in, inlen) <= 0) {
    // OpenSSL 3.x may return failure when recovering empty plaintext
    // In this case outlen is not updated from the initial buffer size
    // Check the error and attempt to handle the empty data case
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));

    // Check if this is an RSA library error that might indicate empty recovered data
    // Error code 0x1C880004 is "RSA lib" error from OpenSSL 3.x provider
    if ((err & 0xFFFFFFF) == 0x1C880004 || (err & 0xFF) == 0x04) {
      ERR_clear_error();
      EVP_PKEY_CTX_free(ctx);
      uint8_t* empty_buf = new uint8_t[1];
      return std::make_shared<NativeArrayBuffer>(empty_buf, 0, [empty_buf]() { delete[] empty_buf; });
    }

    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("Private decryption failed: " + std::string(err_buf));
  }

  EVP_PKEY_CTX_free(ctx);

  uint8_t* raw_ptr = out_buf.get();
  return std::make_shared<NativeArrayBuffer>(out_buf.release(), outlen, [raw_ptr]() { delete[] raw_ptr; });
}

void HybridRsaCipher::loadHybridMethods() {
  registerHybrids(this, [](Prototype& prototype) {
    prototype.registerHybridMethod("encrypt", &HybridRsaCipher::encrypt);
    prototype.registerHybridMethod("decrypt", &HybridRsaCipher::decrypt);
    prototype.registerHybridMethod("privateEncrypt", &HybridRsaCipher::privateEncrypt);
    prototype.registerHybridMethod("privateDecrypt", &HybridRsaCipher::privateDecrypt);
  });
}

} // namespace margelo::nitro::crypto
