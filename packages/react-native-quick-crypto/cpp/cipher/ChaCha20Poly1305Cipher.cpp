#include "ChaCha20Poly1305Cipher.hpp"
#include "QuickCryptoUtils.hpp"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdexcept>

namespace margelo::nitro::crypto {

void ChaCha20Poly1305Cipher::init(const std::shared_ptr<ArrayBuffer> cipher_key, const std::shared_ptr<ArrayBuffer> iv) {
  // Resetting the unique_ptr frees any previous context.
  ctx.reset();

  // Get ChaCha20-Poly1305 cipher implementation
  const EVP_CIPHER* cipher = EVP_chacha20_poly1305();
  if (!cipher) {
    throw std::runtime_error("Failed to get ChaCha20-Poly1305 cipher implementation");
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
    throw std::runtime_error("ChaCha20Poly1305Cipher: Failed initial CipherInit setup: " + std::string(err_buf));
  }

  // Set key and IV
  // Validate key size
  if (cipher_key->size() != kKeySize) {
    throw std::runtime_error("ChaCha20-Poly1305 key must be 32 bytes");
  }

  // Validate nonce size
  if (iv->size() != kNonceSize) {
    throw std::runtime_error("ChaCha20-Poly1305 nonce must be 12 bytes");
  }

  const unsigned char* key_ptr = reinterpret_cast<const unsigned char*>(cipher_key->data());
  const unsigned char* iv_ptr = reinterpret_cast<const unsigned char*>(iv->data());

  if (EVP_CipherInit_ex(ctx.get(), nullptr, nullptr, key_ptr, iv_ptr, is_cipher) != 1) {
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    ctx.reset();
    throw std::runtime_error("ChaCha20Poly1305Cipher: Failed to set key/IV: " + std::string(err_buf));
  }
  is_finalized = false;
  has_update_called = false;
  has_aad = false;
  pending_auth_failed = false;
  auth_tag_state = kAuthTagUnknown;
}

std::shared_ptr<ArrayBuffer> ChaCha20Poly1305Cipher::update(const std::shared_ptr<ArrayBuffer>& data) {
  checkCtx();
  checkNotFinalized();
  has_update_called = true;
  size_t in_len = data->size();
  if (in_len > INT_MAX) {
    throw std::runtime_error("Message too long");
  }

  // For ChaCha20-Poly1305, output size equals input size since it's a stream cipher
  int out_len = in_len;
  auto out_buf = std::make_unique<uint8_t[]>(out_len);

  // Perform the cipher update operation
  if (EVP_CipherUpdate(ctx.get(), out_buf.get(), &out_len, data->data(), in_len) != 1) {
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error("ChaCha20Poly1305Cipher: Failed to update: " + std::string(err_buf));
  }

  // Create and return a new buffer of exact size needed
  uint8_t* raw_ptr = out_buf.get();
  return std::make_shared<NativeArrayBuffer>(out_buf.release(), out_len, [raw_ptr]() { delete[] raw_ptr; });
}

std::shared_ptr<ArrayBuffer> ChaCha20Poly1305Cipher::final() {
  checkCtx();
  checkNotFinalized();

  // For decryption, the auth tag must have been provided via setAuthTag
  // before final(). OpenSSL's ChaCha20-Poly1305 EVP_CipherFinal_ex does
  // not flag a missing tag as an error (it simply doesn't verify), which
  // would silently accept unauthenticated ciphertext — defeating the whole
  // point of an AEAD. Enforce the precondition explicitly.
  if (!is_cipher && auth_tag_state == kAuthTagUnknown) {
    throw std::runtime_error("Unsupported state or unable to authenticate data");
  }

  // For ChaCha20-Poly1305, we need to call final to generate the tag
  int out_len = 0;
  auto out_buf = std::make_unique<unsigned char[]>(0);

  if (EVP_CipherFinal_ex(ctx.get(), out_buf.get(), &out_len) != 1) {
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error("ChaCha20Poly1305Cipher: Failed to finalize: " + std::string(err_buf));
  }

  is_finalized = true;
  unsigned char* raw_ptr = out_buf.get();
  return std::make_shared<NativeArrayBuffer>(out_buf.release(), out_len, [raw_ptr]() { delete[] raw_ptr; });
}

bool ChaCha20Poly1305Cipher::setAAD(const std::shared_ptr<ArrayBuffer>& data, std::optional<double> plaintextLength) {
  checkCtx();
  checkAADBeforeUpdate();
  size_t aad_len = data->size();

  // Set AAD data
  int out_len = 0;
  if (EVP_CipherUpdate(ctx.get(), nullptr, &out_len, data->data(), aad_len) != 1) {
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
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, kTagSize, tag_buf.get()) != 1) {
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

  if (tag->size() != kTagSize) {
    throw std::runtime_error("ChaCha20-Poly1305 tag must be 16 bytes");
  }

  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, kTagSize, tag->data()) != 1) {
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error("ChaCha20Poly1305Cipher: Failed to set auth tag: " + std::string(err_buf));
  }
  auth_tag_state = kAuthTagPassedToOpenSSL;
  return true;
}

} // namespace margelo::nitro::crypto
