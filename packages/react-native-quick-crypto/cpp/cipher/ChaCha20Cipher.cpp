#include "ChaCha20Cipher.hpp"
#include "QuickCryptoUtils.hpp"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdexcept>

namespace margelo::nitro::crypto {

void ChaCha20Cipher::init(const std::shared_ptr<ArrayBuffer> cipher_key, const std::shared_ptr<ArrayBuffer> iv) {
  // Resetting the unique_ptr frees any previous context.
  ctx.reset();

  // Get ChaCha20 cipher implementation
  const EVP_CIPHER* cipher = EVP_chacha20();
  if (!cipher) {
    throw std::runtime_error("Failed to get ChaCha20 cipher implementation");
  }

  // Create a new context
  ctx.reset(EVP_CIPHER_CTX_new());
  if (!ctx) {
    throw std::runtime_error("Failed to create cipher context");
  }

  // Initialize the encryption/decryption operation
  if (EVP_CipherInit_ex(ctx.get(), cipher, nullptr, nullptr, nullptr, is_cipher) != 1) {
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    ctx.reset();
    throw std::runtime_error("ChaCha20Cipher: Failed initial CipherInit setup: " + std::string(err_buf));
  }

  // Set key and IV
  // Validate key size
  if (cipher_key->size() != kKeySize) {
    throw std::runtime_error("ChaCha20 key must be 32 bytes");
  }

  // Validate IV size
  if (iv->size() != kIVSize) {
    throw std::runtime_error("ChaCha20 IV must be 16 bytes");
  }

  const unsigned char* key_ptr = reinterpret_cast<const unsigned char*>(cipher_key->data());
  const unsigned char* iv_ptr = reinterpret_cast<const unsigned char*>(iv->data());

  if (EVP_CipherInit_ex(ctx.get(), nullptr, nullptr, key_ptr, iv_ptr, is_cipher) != 1) {
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    ctx.reset();
    throw std::runtime_error("ChaCha20Cipher: Failed to set key/IV: " + std::string(err_buf));
  }
}

std::shared_ptr<ArrayBuffer> ChaCha20Cipher::update(const std::shared_ptr<ArrayBuffer>& data) {
  checkCtx();
  checkNotFinalized();
  size_t in_len = data->size();
  if (in_len > INT_MAX) {
    throw std::runtime_error("Message too long");
  }

  // For ChaCha20, output size equals input size since it's a stream cipher
  int out_len = in_len;
  auto out_buf = std::make_unique<uint8_t[]>(out_len);

  // Perform the cipher update operation
  if (EVP_CipherUpdate(ctx.get(), out_buf.get(), &out_len, data->data(), in_len) != 1) {
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error("ChaCha20Cipher: Failed to update: " + std::string(err_buf));
  }

  // Create and return a new buffer of exact size needed
  uint8_t* raw_ptr = out_buf.get();
  return std::make_shared<NativeArrayBuffer>(out_buf.release(), out_len, [raw_ptr]() { delete[] raw_ptr; });
}

std::shared_ptr<ArrayBuffer> ChaCha20Cipher::final() {
  checkCtx();
  checkNotFinalized();
  is_finalized = true;
  auto empty_buf = std::make_unique<unsigned char[]>(0);
  unsigned char* raw_ptr = empty_buf.get();
  return std::make_shared<NativeArrayBuffer>(empty_buf.release(), 0, [raw_ptr]() { delete[] raw_ptr; });
}

} // namespace margelo::nitro::crypto
