#include "XSalsa20Poly1305Cipher.hpp"

#include <cstring>
#include <stdexcept>

#include "NitroModules/ArrayBuffer.hpp"
#include "QuickCryptoUtils.hpp"

namespace margelo::nitro::crypto {

XSalsa20Poly1305Cipher::~XSalsa20Poly1305Cipher() {
  // Always wipe via OPENSSL_cleanse (even when libsodium is enabled) so the
  // non-sodium `std::memset` fallback can't be optimized away by the
  // compiler. Audit MEDIUM finding (XSalsa20Poly1305Cipher.cpp:20-22).
  secureZero(key_);
  secureZero(nonce_);
  secureZero(auth_tag_);
  secureZero(data_buffer_);
  data_buffer_.clear();
}

void XSalsa20Poly1305Cipher::init(const std::shared_ptr<ArrayBuffer> cipher_key, const std::shared_ptr<ArrayBuffer> iv) {
  if (cipher_key->size() != kKeySize) {
    throw std::runtime_error("XSalsa20-Poly1305 key must be 32 bytes, got " + std::to_string(cipher_key->size()) + " bytes");
  }

  if (iv->size() != kNonceSize) {
    throw std::runtime_error("XSalsa20-Poly1305 nonce must be 24 bytes, got " + std::to_string(iv->size()) + " bytes");
  }

  std::memcpy(key_, cipher_key->data(), kKeySize);
  std::memcpy(nonce_, iv->data(), kNonceSize);

  data_buffer_.clear();
  is_finalized = false;
}

std::shared_ptr<ArrayBuffer> XSalsa20Poly1305Cipher::update(const std::shared_ptr<ArrayBuffer>& data) {
  checkNotFinalized();
#ifndef BLSALLOC_SODIUM
  throw std::runtime_error("XSalsa20Poly1305Cipher: libsodium must be enabled (BLSALLOC_SODIUM)");
#else
  size_t data_len = data->size();

  size_t old_size = data_buffer_.size();
  data_buffer_.resize(old_size + data_len);
  std::memcpy(data_buffer_.data() + old_size, data->data(), data_len);

  return std::make_shared<NativeArrayBuffer>(nullptr, 0, nullptr);
#endif
}

std::shared_ptr<ArrayBuffer> XSalsa20Poly1305Cipher::final() {
  checkNotFinalized();
#ifndef BLSALLOC_SODIUM
  throw std::runtime_error("XSalsa20Poly1305Cipher: libsodium must be enabled (BLSALLOC_SODIUM)");
#else
  if (is_cipher) {
    auto ciphertext = std::make_unique<uint8_t[]>(data_buffer_.size());

    int result = crypto_secretbox_detached(ciphertext.get(), auth_tag_, data_buffer_.data(), data_buffer_.size(), nonce_, key_);

    if (result != 0) {
      sodium_memzero(ciphertext.get(), data_buffer_.size());
      throw std::runtime_error("XSalsa20Poly1305Cipher: encryption failed");
    }

    is_finalized = true;
    size_t ct_len = data_buffer_.size();
    uint8_t* raw_ptr = ciphertext.get();
    return std::make_shared<NativeArrayBuffer>(ciphertext.release(), ct_len, [raw_ptr]() { delete[] raw_ptr; });
  } else {
    if (data_buffer_.empty()) {
      is_finalized = true;
      return std::make_shared<NativeArrayBuffer>(nullptr, 0, nullptr);
    }

    auto plaintext = std::make_unique<uint8_t[]>(data_buffer_.size());

    int result = crypto_secretbox_open_detached(plaintext.get(), data_buffer_.data(), auth_tag_, data_buffer_.size(), nonce_, key_);

    if (result != 0) {
      sodium_memzero(plaintext.get(), data_buffer_.size());
      throw std::runtime_error("XSalsa20Poly1305Cipher: decryption failed - authentication tag mismatch");
    }

    is_finalized = true;
    size_t pt_len = data_buffer_.size();
    uint8_t* raw_ptr = plaintext.get();
    return std::make_shared<NativeArrayBuffer>(plaintext.release(), pt_len, [raw_ptr]() { delete[] raw_ptr; });
  }
#endif
}

bool XSalsa20Poly1305Cipher::setAAD(const std::shared_ptr<ArrayBuffer>& data, std::optional<double> plaintextLength) {
  throw std::runtime_error("AAD is not supported for xsalsa20-poly1305 (use xchacha20-poly1305 instead)");
}

std::shared_ptr<ArrayBuffer> XSalsa20Poly1305Cipher::getAuthTag() {
#ifndef BLSALLOC_SODIUM
  throw std::runtime_error("XSalsa20Poly1305Cipher: libsodium must be enabled (BLSALLOC_SODIUM)");
#else
  if (!is_cipher) {
    throw std::runtime_error("getAuthTag can only be called during encryption");
  }
  if (!is_finalized) {
    throw std::runtime_error("getAuthTag must be called after final()");
  }

  auto tag_copy = std::make_unique<uint8_t[]>(kTagSize);
  std::memcpy(tag_copy.get(), auth_tag_, kTagSize);
  uint8_t* raw_ptr = tag_copy.get();
  return std::make_shared<NativeArrayBuffer>(tag_copy.release(), kTagSize, [raw_ptr]() { delete[] raw_ptr; });
#endif
}

bool XSalsa20Poly1305Cipher::setAuthTag(const std::shared_ptr<ArrayBuffer>& tag) {
#ifndef BLSALLOC_SODIUM
  throw std::runtime_error("XSalsa20Poly1305Cipher: libsodium must be enabled (BLSALLOC_SODIUM)");
#else
  if (is_cipher) {
    throw std::runtime_error("setAuthTag can only be called during decryption");
  }

  if (tag->size() != kTagSize) {
    throw std::runtime_error("XSalsa20-Poly1305 tag must be 16 bytes, got " + std::to_string(tag->size()) + " bytes");
  }

  std::memcpy(auth_tag_, tag->data(), kTagSize);
  return true;
#endif
}

bool XSalsa20Poly1305Cipher::setAutoPadding(bool autoPad) {
  throw std::runtime_error("setAutoPadding is not supported for xsalsa20-poly1305");
}

} // namespace margelo::nitro::crypto
