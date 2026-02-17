#include "ChaCha20Poly1305Cipher.hpp"
#include "QuickCryptoUtils.hpp"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdexcept>

namespace margelo::nitro::crypto {

void ChaCha20Poly1305Cipher::init(const std::shared_ptr<ArrayBuffer> cipher_key, const std::shared_ptr<ArrayBuffer> iv) {
  // Clean up any existing context
  if (ctx) {
    EVP_CIPHER_CTX_free(ctx);
    ctx = nullptr;
  }

  // Get ChaCha20-Poly1305 cipher implementation
  const EVP_CIPHER* cipher = EVP_chacha20_poly1305();
  if (!cipher) {
    throw std::runtime_error("Failed to get ChaCha20-Poly1305 cipher implementation");
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
    throw std::runtime_error("ChaCha20Poly1305Cipher: Failed initial CipherInit setup: " + std::string(err_buf));
  }

  // Set key and IV
  auto native_key = ToNativeArrayBuffer(cipher_key);
  auto native_iv = ToNativeArrayBuffer(iv);

  // Validate key size
  if (native_key->size() != kKeySize) {
    throw std::runtime_error("ChaCha20-Poly1305 key must be 32 bytes");
  }

  // Validate nonce size
  if (native_iv->size() != kNonceSize) {
    throw std::runtime_error("ChaCha20-Poly1305 nonce must be 12 bytes");
  }

  const unsigned char* key_ptr = reinterpret_cast<const unsigned char*>(native_key->data());
  const unsigned char* iv_ptr = reinterpret_cast<const unsigned char*>(native_iv->data());

  if (EVP_CipherInit_ex(ctx, nullptr, nullptr, key_ptr, iv_ptr, is_cipher) != 1) {
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    EVP_CIPHER_CTX_free(ctx);
    ctx = nullptr;
    throw std::runtime_error("ChaCha20Poly1305Cipher: Failed to set key/IV: " + std::string(err_buf));
  }
  is_finalized = false;
}

std::shared_ptr<ArrayBuffer> ChaCha20Poly1305Cipher::update(const std::shared_ptr<ArrayBuffer>& data) {
  checkCtx();
  checkNotFinalized();
  auto native_data = ToNativeArrayBuffer(data);
  size_t in_len = native_data->size();
  if (in_len > INT_MAX) {
    throw std::runtime_error("Message too long");
  }

  // For ChaCha20-Poly1305, output size equals input size since it's a stream cipher
  int out_len = in_len;
  uint8_t* out = new uint8_t[out_len];

  // Perform the cipher update operation
  if (EVP_CipherUpdate(ctx, out, &out_len, native_data->data(), in_len) != 1) {
    delete[] out;
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error("ChaCha20Poly1305Cipher: Failed to update: " + std::string(err_buf));
  }

  // Create and return a new buffer of exact size needed
  return std::make_shared<NativeArrayBuffer>(out, out_len, [=]() { delete[] out; });
}

std::shared_ptr<ArrayBuffer> ChaCha20Poly1305Cipher::final() {
  checkCtx();
  checkNotFinalized();

  // For ChaCha20-Poly1305, we need to call final to generate the tag
  int out_len = 0;
  unsigned char* out = new unsigned char[0];

  if (EVP_CipherFinal_ex(ctx, out, &out_len) != 1) {
    delete[] out;
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error("ChaCha20Poly1305Cipher: Failed to finalize: " + std::string(err_buf));
  }

  is_finalized = true;
  return std::make_shared<NativeArrayBuffer>(out, out_len, [=]() { delete[] out; });
}

bool ChaCha20Poly1305Cipher::setAAD(const std::shared_ptr<ArrayBuffer>& data, std::optional<double> plaintextLength) {
  checkCtx();
  auto native_aad = ToNativeArrayBuffer(data);
  size_t aad_len = native_aad->size();

  // Set AAD data
  int out_len = 0;
  if (EVP_CipherUpdate(ctx, nullptr, &out_len, native_aad->data(), aad_len) != 1) {
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error("ChaCha20Poly1305Cipher: Failed to set AAD: " + std::string(err_buf));
  }
  return true;
}

std::shared_ptr<ArrayBuffer> ChaCha20Poly1305Cipher::getAuthTag() {
  checkCtx();
  if (!is_cipher) {
    throw std::runtime_error("getAuthTag can only be called during encryption");
  }
  if (!is_finalized) {
    throw std::runtime_error("getAuthTag must be called after final()");
  }

  // Get the authentication tag
  auto tag_buf = std::make_unique<uint8_t[]>(kTagSize);
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, kTagSize, tag_buf.get()) != 1) {
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error("ChaCha20Poly1305Cipher: Failed to get auth tag: " + std::string(err_buf));
  }

  uint8_t* raw_ptr = tag_buf.get();
  return std::make_shared<NativeArrayBuffer>(tag_buf.release(), kTagSize, [raw_ptr]() { delete[] raw_ptr; });
}

bool ChaCha20Poly1305Cipher::setAuthTag(const std::shared_ptr<ArrayBuffer>& tag) {
  checkCtx();
  if (is_cipher) {
    throw std::runtime_error("setAuthTag can only be called during decryption");
  }

  auto native_tag = ToNativeArrayBuffer(tag);
  if (native_tag->size() != kTagSize) {
    throw std::runtime_error("ChaCha20-Poly1305 tag must be 16 bytes");
  }

  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, kTagSize, native_tag->data()) != 1) {
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error("ChaCha20Poly1305Cipher: Failed to set auth tag: " + std::string(err_buf));
  }
  return true;
}

} // namespace margelo::nitro::crypto
