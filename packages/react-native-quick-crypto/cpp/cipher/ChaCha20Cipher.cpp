#include "ChaCha20Cipher.hpp"
#include "Utils.hpp"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdexcept>

namespace margelo::nitro::crypto {

void ChaCha20Cipher::init(const std::shared_ptr<ArrayBuffer> cipher_key, const std::shared_ptr<ArrayBuffer> iv) {
  // Clean up any existing context
  if (ctx) {
    EVP_CIPHER_CTX_free(ctx);
    ctx = nullptr;
  }

  // Get ChaCha20 cipher implementation
  const EVP_CIPHER* cipher = EVP_chacha20();
  if (!cipher) {
    throw std::runtime_error("Failed to get ChaCha20 cipher implementation");
  }

  // Create a new context
  ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    throw std::runtime_error("Failed to create cipher context");
  }

  // Initialize the encryption/decryption operation
  if (EVP_CipherInit_ex(ctx, cipher, nullptr, nullptr, nullptr, is_cipher) != 1) {
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    EVP_CIPHER_CTX_free(ctx);
    ctx = nullptr;
    throw std::runtime_error("ChaCha20Cipher: Failed initial CipherInit setup: " + std::string(err_buf));
  }

  // Set key and IV
  auto native_key = ToNativeArrayBuffer(cipher_key);
  auto native_iv = ToNativeArrayBuffer(iv);

  // Validate key size
  if (native_key->size() != kKeySize) {
    throw std::runtime_error("ChaCha20 key must be 32 bytes");
  }

  // Validate IV size
  if (native_iv->size() != kIVSize) {
    throw std::runtime_error("ChaCha20 IV must be 16 bytes");
  }

  const unsigned char* key_ptr = reinterpret_cast<const unsigned char*>(native_key->data());
  const unsigned char* iv_ptr = reinterpret_cast<const unsigned char*>(native_iv->data());

  if (EVP_CipherInit_ex(ctx, nullptr, nullptr, key_ptr, iv_ptr, is_cipher) != 1) {
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    EVP_CIPHER_CTX_free(ctx);
    ctx = nullptr;
    throw std::runtime_error("ChaCha20Cipher: Failed to set key/IV: " + std::string(err_buf));
  }
}

std::shared_ptr<ArrayBuffer> ChaCha20Cipher::update(const std::shared_ptr<ArrayBuffer>& data) {
  checkCtx();
  auto native_data = ToNativeArrayBuffer(data);
  size_t in_len = native_data->size();
  if (in_len > INT_MAX) {
    throw std::runtime_error("Message too long");
  }

  // For ChaCha20, output size equals input size since it's a stream cipher
  int out_len = in_len;
  uint8_t* out = new uint8_t[out_len];

  // Perform the cipher update operation
  if (EVP_CipherUpdate(ctx, out, &out_len, native_data->data(), in_len) != 1) {
    delete[] out;
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error("ChaCha20Cipher: Failed to update: " + std::string(err_buf));
  }

  // Create and return a new buffer of exact size needed
  return std::make_shared<NativeArrayBuffer>(out, out_len, [=]() { delete[] out; });
}

std::shared_ptr<ArrayBuffer> ChaCha20Cipher::final() {
  checkCtx();
  // For ChaCha20, final() should return an empty buffer since it's a stream cipher
  unsigned char* empty_output = new unsigned char[0];
  return std::make_shared<NativeArrayBuffer>(empty_output, 0, [=]() { delete[] empty_output; });
}

} // namespace margelo::nitro::crypto
