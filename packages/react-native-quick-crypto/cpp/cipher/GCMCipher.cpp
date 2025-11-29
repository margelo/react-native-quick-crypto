#include "GCMCipher.hpp"
#include "Utils.hpp"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdexcept>

namespace margelo::nitro::crypto {

void GCMCipher::init(const std::shared_ptr<ArrayBuffer> cipher_key, const std::shared_ptr<ArrayBuffer> iv) {
  // Clean up any existing context
  if (ctx) {
    EVP_CIPHER_CTX_free(ctx);
    ctx = nullptr;
  }

  // 1. Get cipher implementation by name
  const EVP_CIPHER* cipher = EVP_get_cipherbyname(cipher_type.c_str());
  if (!cipher) {
    throw std::runtime_error("Unknown cipher " + cipher_type);
  }

  // 2. Create a new context
  ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    throw std::runtime_error("Failed to create cipher context");
  }

  // 3. Initialize with cipher type only (no key/IV yet)
  if (EVP_CipherInit_ex(ctx, cipher, nullptr, nullptr, nullptr, is_cipher) != 1) {
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    EVP_CIPHER_CTX_free(ctx);
    ctx = nullptr;
    throw std::runtime_error("GCMCipher: Failed initial CipherInit setup: " + std::string(err_buf));
  }

  // 4. Set IV length for non-standard IV sizes (GCM default is 96 bits/12 bytes)
  auto native_iv = ToNativeArrayBuffer(iv);
  size_t iv_len = native_iv->size();

  if (iv_len != 12) { // Only set if not the default length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv_len), nullptr) != 1) {
      unsigned long err = ERR_get_error();
      char err_buf[256];
      ERR_error_string_n(err, err_buf, sizeof(err_buf));
      EVP_CIPHER_CTX_free(ctx);
      ctx = nullptr;
      throw std::runtime_error("GCMCipher: Failed to set IV length: " + std::string(err_buf));
    }
  }

  // 5. Now set the key and IV
  auto native_key = ToNativeArrayBuffer(cipher_key);
  const unsigned char* key_ptr = reinterpret_cast<const unsigned char*>(native_key->data());
  const unsigned char* iv_ptr = reinterpret_cast<const unsigned char*>(native_iv->data());

  if (EVP_CipherInit_ex(ctx, nullptr, nullptr, key_ptr, iv_ptr, is_cipher) != 1) {
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    EVP_CIPHER_CTX_free(ctx);
    ctx = nullptr;
    throw std::runtime_error("GCMCipher: Failed to set key/IV: " + std::string(err_buf));
  }
}

} // namespace margelo::nitro::crypto
