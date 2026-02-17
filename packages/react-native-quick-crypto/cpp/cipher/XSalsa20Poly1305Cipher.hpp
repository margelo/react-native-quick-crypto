#pragma once

#ifdef BLSALLOC_SODIUM
#include "sodium.h"
#else
#define crypto_secretbox_xsalsa20poly1305_KEYBYTES 32U
#define crypto_secretbox_xsalsa20poly1305_NONCEBYTES 24U
#define crypto_secretbox_xsalsa20poly1305_MACBYTES 16U
#endif

#include <vector>

#include "HybridCipher.hpp"

namespace margelo::nitro::crypto {

class XSalsa20Poly1305Cipher : public HybridCipher {
 public:
  XSalsa20Poly1305Cipher() : HybridObject(TAG) {}
  ~XSalsa20Poly1305Cipher();

  void init(const std::shared_ptr<ArrayBuffer> cipher_key, const std::shared_ptr<ArrayBuffer> iv) override;
  std::shared_ptr<ArrayBuffer> update(const std::shared_ptr<ArrayBuffer>& data) override;
  std::shared_ptr<ArrayBuffer> final() override;
  bool setAAD(const std::shared_ptr<ArrayBuffer>& data, std::optional<double> plaintextLength) override;
  std::shared_ptr<ArrayBuffer> getAuthTag() override;
  bool setAuthTag(const std::shared_ptr<ArrayBuffer>& tag) override;
  bool setAutoPadding(bool autoPad) override;

 private:
  static constexpr size_t kKeySize = crypto_secretbox_xsalsa20poly1305_KEYBYTES;
  static constexpr size_t kNonceSize = crypto_secretbox_xsalsa20poly1305_NONCEBYTES;
  static constexpr size_t kTagSize = crypto_secretbox_xsalsa20poly1305_MACBYTES;

  uint8_t key_[kKeySize];
  uint8_t nonce_[kNonceSize];
  std::vector<uint8_t> data_buffer_;
  uint8_t auth_tag_[kTagSize];
};

} // namespace margelo::nitro::crypto
