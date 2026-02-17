#include "XChaCha20Poly1305Cipher.hpp"

#include <cstring>
#include <stdexcept>

#include "NitroModules/ArrayBuffer.hpp"
#include "QuickCryptoUtils.hpp"

namespace margelo::nitro::crypto {

XChaCha20Poly1305Cipher::~XChaCha20Poly1305Cipher() {
#ifdef BLSALLOC_SODIUM
  sodium_memzero(key_, kKeySize);
  sodium_memzero(nonce_, kNonceSize);
  sodium_memzero(auth_tag_, kTagSize);
  if (!data_buffer_.empty()) {
    sodium_memzero(data_buffer_.data(), data_buffer_.size());
  }
  if (!aad_.empty()) {
    sodium_memzero(aad_.data(), aad_.size());
  }
#else
  std::memset(key_, 0, kKeySize);
  std::memset(nonce_, 0, kNonceSize);
  std::memset(auth_tag_, 0, kTagSize);
#endif
  data_buffer_.clear();
  aad_.clear();
}

void XChaCha20Poly1305Cipher::init(const std::shared_ptr<ArrayBuffer> cipher_key, const std::shared_ptr<ArrayBuffer> iv) {
  auto native_key = ToNativeArrayBuffer(cipher_key);
  auto native_iv = ToNativeArrayBuffer(iv);

  if (native_key->size() != kKeySize) {
    throw std::runtime_error("XChaCha20-Poly1305 key must be 32 bytes, got " + std::to_string(native_key->size()) + " bytes");
  }

  if (native_iv->size() != kNonceSize) {
    throw std::runtime_error("XChaCha20-Poly1305 nonce must be 24 bytes, got " + std::to_string(native_iv->size()) + " bytes");
  }

  std::memcpy(key_, native_key->data(), kKeySize);
  std::memcpy(nonce_, native_iv->data(), kNonceSize);

  data_buffer_.clear();
  aad_.clear();
}

std::shared_ptr<ArrayBuffer> XChaCha20Poly1305Cipher::update(const std::shared_ptr<ArrayBuffer>& data) {
  checkNotFinalized();
#ifndef BLSALLOC_SODIUM
  throw std::runtime_error("XChaCha20Poly1305Cipher: libsodium must be enabled (BLSALLOC_SODIUM)");
#else
  auto native_data = ToNativeArrayBuffer(data);
  size_t data_len = native_data->size();

  size_t old_size = data_buffer_.size();
  data_buffer_.resize(old_size + data_len);
  std::memcpy(data_buffer_.data() + old_size, native_data->data(), data_len);

  return std::make_shared<NativeArrayBuffer>(nullptr, 0, nullptr);
#endif
}

std::shared_ptr<ArrayBuffer> XChaCha20Poly1305Cipher::final() {
  checkNotFinalized();
#ifndef BLSALLOC_SODIUM
  throw std::runtime_error("XChaCha20Poly1305Cipher: libsodium must be enabled (BLSALLOC_SODIUM)");
#else
  if (is_cipher) {
    uint8_t* ciphertext = new uint8_t[data_buffer_.size()];

    int result =
        crypto_aead_xchacha20poly1305_ietf_encrypt_detached(ciphertext, auth_tag_, nullptr, data_buffer_.data(), data_buffer_.size(),
                                                            aad_.empty() ? nullptr : aad_.data(), aad_.size(), nullptr, nonce_, key_);

    if (result != 0) {
      sodium_memzero(ciphertext, data_buffer_.size());
      delete[] ciphertext;
      throw std::runtime_error("XChaCha20Poly1305Cipher: encryption failed");
    }

    is_finalized = true;
    size_t ct_len = data_buffer_.size();
    return std::make_shared<NativeArrayBuffer>(ciphertext, ct_len, [=]() { delete[] ciphertext; });
  } else {
    if (data_buffer_.empty()) {
      is_finalized = true;
      return std::make_shared<NativeArrayBuffer>(nullptr, 0, nullptr);
    }

    uint8_t* plaintext = new uint8_t[data_buffer_.size()];

    int result =
        crypto_aead_xchacha20poly1305_ietf_decrypt_detached(plaintext, nullptr, data_buffer_.data(), data_buffer_.size(), auth_tag_,
                                                            aad_.empty() ? nullptr : aad_.data(), aad_.size(), nonce_, key_);

    if (result != 0) {
      sodium_memzero(plaintext, data_buffer_.size());
      delete[] plaintext;
      throw std::runtime_error("XChaCha20Poly1305Cipher: decryption failed - authentication tag mismatch");
    }

    is_finalized = true;
    size_t pt_len = data_buffer_.size();
    return std::make_shared<NativeArrayBuffer>(plaintext, pt_len, [=]() { delete[] plaintext; });
  }
#endif
}

bool XChaCha20Poly1305Cipher::setAAD(const std::shared_ptr<ArrayBuffer>& data, std::optional<double> plaintextLength) {
#ifndef BLSALLOC_SODIUM
  throw std::runtime_error("XChaCha20Poly1305Cipher: libsodium must be enabled (BLSALLOC_SODIUM)");
#else
  auto native_aad = ToNativeArrayBuffer(data);
  aad_.resize(native_aad->size());
  std::memcpy(aad_.data(), native_aad->data(), native_aad->size());
  return true;
#endif
}

std::shared_ptr<ArrayBuffer> XChaCha20Poly1305Cipher::getAuthTag() {
#ifndef BLSALLOC_SODIUM
  throw std::runtime_error("XChaCha20Poly1305Cipher: libsodium must be enabled (BLSALLOC_SODIUM)");
#else
  if (!is_cipher) {
    throw std::runtime_error("getAuthTag can only be called during encryption");
  }
  if (!is_finalized) {
    throw std::runtime_error("getAuthTag must be called after final()");
  }

  uint8_t* tag_copy = new uint8_t[kTagSize];
  std::memcpy(tag_copy, auth_tag_, kTagSize);
  return std::make_shared<NativeArrayBuffer>(tag_copy, kTagSize, [=]() { delete[] tag_copy; });
#endif
}

bool XChaCha20Poly1305Cipher::setAuthTag(const std::shared_ptr<ArrayBuffer>& tag) {
#ifndef BLSALLOC_SODIUM
  throw std::runtime_error("XChaCha20Poly1305Cipher: libsodium must be enabled (BLSALLOC_SODIUM)");
#else
  if (is_cipher) {
    throw std::runtime_error("setAuthTag can only be called during decryption");
  }

  auto native_tag = ToNativeArrayBuffer(tag);
  if (native_tag->size() != kTagSize) {
    throw std::runtime_error("XChaCha20-Poly1305 tag must be 16 bytes, got " + std::to_string(native_tag->size()) + " bytes");
  }

  std::memcpy(auth_tag_, native_tag->data(), kTagSize);
  return true;
#endif
}

bool XChaCha20Poly1305Cipher::setAutoPadding(bool autoPad) {
  throw std::runtime_error("setAutoPadding is not supported for xchacha20-poly1305");
}

} // namespace margelo::nitro::crypto
