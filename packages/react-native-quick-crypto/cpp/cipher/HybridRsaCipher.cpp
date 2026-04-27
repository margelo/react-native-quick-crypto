#include "HybridRsaCipher.hpp"
#include "../keys/HybridKeyObjectHandle.hpp"
#include "QuickCryptoUtils.hpp"

#include <cstring>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

namespace margelo::nitro::crypto {

using margelo::nitro::NativeArrayBuffer;

constexpr int kRsaPkcs1Padding = 1;
constexpr int kRsaOaepPadding = 4;

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

// Bleichenbacher mitigation. For RSA PKCS#1 v1.5 decryption, ask OpenSSL to
// substitute random-looking plaintext on padding-check failure rather than
// surfacing a distinguishable error. This closes the "padding-valid /
// padding-invalid" oracle that the Million Message Attack depends on. The
// `EVP_PKEY_CTX_ctrl_str` knob was added in OpenSSL 3.2; if the underlying
// build does not support it (BoringSSL, older OpenSSL) we refuse to perform
// PKCS#1 v1.5 decryption rather than silently fall back to a configuration
// that leaves the timing-side oracle open. Node.js (`crypto_cipher.cc`)
// applies the same hard-fail policy. Returns true if implicit rejection is
// engaged or not applicable (OAEP); false if PKCS#1 v1.5 was requested but
// the knob failed. Always clears the OpenSSL error stack on failure so a
// rejected knob does not leak through to a later operation.
[[nodiscard]] static bool enableImplicitRejectionIfPkcs1(EVP_PKEY_CTX* ctx, int opensslPadding) {
  if (opensslPadding != RSA_PKCS1_PADDING) {
    return true;
  }
  bool ok = EVP_PKEY_CTX_ctrl_str(ctx, "rsa_pkcs1_implicit_rejection", "1") > 0;
  if (!ok) {
    ERR_clear_error();
  }
  return ok;
}

// Throw the SAME message regardless of the underlying OpenSSL error so that
// callers (and remote attackers in oracle-style scenarios) cannot distinguish
// "padding invalid" from "data too large", "bad version", "wrong key", etc.
// The OpenSSL error stack is cleared so it is not observable later.
[[noreturn]] static void throwOpaqueDecryptFailure() {
  ERR_clear_error();
  throw std::runtime_error("RSA decryption failed");
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

  if (!enableImplicitRejectionIfPkcs1(ctx, opensslPadding)) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("RSA PKCS#1 v1.5 decryption requires OpenSSL implicit-rejection support (>= 3.2)");
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

  // Both decrypt calls below operate on attacker-controlled ciphertext, so
  // any failure must be surfaced with an opaque, content-independent message.
  // See enableImplicitRejectionIfPkcs1 / throwOpaqueDecryptFailure above.
  size_t outlen;
  if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, in, inlen) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    throwOpaqueDecryptFailure();
  }

  auto out_buf = std::make_unique<uint8_t[]>(outlen);

  if (EVP_PKEY_decrypt(ctx, out_buf.get(), &outlen, in, inlen) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    throwOpaqueDecryptFailure();
  }

  EVP_PKEY_CTX_free(ctx);

  uint8_t* raw_ptr = out_buf.get();
  return std::make_shared<NativeArrayBuffer>(out_buf.release(), outlen, [raw_ptr]() { delete[] raw_ptr; });
}

std::shared_ptr<ArrayBuffer> HybridRsaCipher::publicDecrypt(const std::shared_ptr<HybridKeyObjectHandleSpec>& keyHandle,
                                                            const std::shared_ptr<ArrayBuffer>& data, double padding) {
  auto keyHandleImpl = std::static_pointer_cast<HybridKeyObjectHandle>(keyHandle);
  EVP_PKEY* pkey = keyHandleImpl->getKeyObjectData().GetAsymmetricKey().get();

  if (!pkey) {
    throw std::runtime_error("Invalid key for RSA public decryption");
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

  // verify_recover acts on attacker-controlled ciphertext too — surface only
  // an opaque error so a remote caller cannot distinguish failure modes.
  size_t outlen;
  if (EVP_PKEY_verify_recover(ctx, nullptr, &outlen, in, inlen) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    throwOpaqueDecryptFailure();
  }

  if (outlen == 0) {
    EVP_PKEY_CTX_free(ctx);
    uint8_t* empty_buf = new uint8_t[1];
    return std::make_shared<NativeArrayBuffer>(empty_buf, 0, [empty_buf]() { delete[] empty_buf; });
  }

  auto out_buf = std::make_unique<uint8_t[]>(outlen);

  if (EVP_PKEY_verify_recover(ctx, out_buf.get(), &outlen, in, inlen) <= 0) {
    // Empty-plaintext recovery: when the original message was zero bytes,
    // OpenSSL's verify_recover surfaces a specific reason code rather than
    // returning success+outlen=0. Match the narrow code from the original
    // implementation and return an empty buffer so `publicDecrypt(privateEncrypt(""))`
    // round-trips. publicDecrypt is signature verification with the PUBLIC
    // key — anyone can perform it — so the special case does not enable a
    // Bleichenbacher-style oracle. The fall-through still uses the opaque
    // throw helper.
    //
    // Use ERR_get_error (oldest in the FIFO queue) to match the inner
    // padding-check error rather than ERR_peek_last_error which returns
    // the outer wrapper code that doesn't satisfy the narrow match.
    unsigned long err = ERR_get_error();
    if ((err & 0xFFFFFFF) == 0x1C880004 || (err & 0xFF) == 0x04) {
      ERR_clear_error();
      EVP_PKEY_CTX_free(ctx);
      uint8_t* empty_buf = new uint8_t[1];
      return std::make_shared<NativeArrayBuffer>(empty_buf, 0, [empty_buf]() { delete[] empty_buf; });
    }
    EVP_PKEY_CTX_free(ctx);
    throwOpaqueDecryptFailure();
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
                                                             const std::shared_ptr<ArrayBuffer>& data, double padding,
                                                             const std::string& hashAlgorithm,
                                                             const std::optional<std::shared_ptr<ArrayBuffer>>& label) {
  auto keyHandleImpl = std::static_pointer_cast<HybridKeyObjectHandle>(keyHandle);
  EVP_PKEY* pkey = keyHandleImpl->getKeyObjectData().GetAsymmetricKey().get();

  if (!pkey) {
    throw std::runtime_error("Invalid key for RSA private decryption");
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

  if (!enableImplicitRejectionIfPkcs1(ctx, opensslPadding)) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("RSA PKCS#1 v1.5 decryption requires OpenSSL implicit-rejection support (>= 3.2)");
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

  // Both decrypt calls below operate on attacker-controlled ciphertext, so
  // any failure must be surfaced with an opaque, content-independent message.
  // See enableImplicitRejectionIfPkcs1 / throwOpaqueDecryptFailure above.
  size_t outlen;
  if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, in, inlen) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    throwOpaqueDecryptFailure();
  }

  auto out_buf = std::make_unique<uint8_t[]>(outlen);

  if (EVP_PKEY_decrypt(ctx, out_buf.get(), &outlen, in, inlen) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    throwOpaqueDecryptFailure();
  }

  EVP_PKEY_CTX_free(ctx);

  uint8_t* raw_ptr = out_buf.get();
  return std::make_shared<NativeArrayBuffer>(out_buf.release(), outlen, [raw_ptr]() { delete[] raw_ptr; });
}

void HybridRsaCipher::loadHybridMethods() {
  registerHybrids(this, [](Prototype& prototype) {
    prototype.registerHybridMethod("encrypt", &HybridRsaCipher::encrypt);
    prototype.registerHybridMethod("decrypt", &HybridRsaCipher::decrypt);
    prototype.registerHybridMethod("publicDecrypt", &HybridRsaCipher::publicDecrypt);
    prototype.registerHybridMethod("privateEncrypt", &HybridRsaCipher::privateEncrypt);
    prototype.registerHybridMethod("privateDecrypt", &HybridRsaCipher::privateDecrypt);
  });
}

} // namespace margelo::nitro::crypto
