#pragma once

#if BLSALLOC_SODIUM
#include "sodium.h"
#else
#define crypto_aead_xchacha20poly1305_ietf_KEYBYTES 32U
#define crypto_aead_xchacha20poly1305_ietf_NPUBBYTES 24U
#define crypto_aead_xchacha20poly1305_ietf_ABYTES 16U
#endif

#include <vector>

#include "HybridCipher.hpp"

namespace margelo::nitro::crypto {

class XChaCha20Poly1305Cipher : public HybridCipher {
 public:
  XChaCha20Poly1305Cipher() : HybridObject(TAG), final_called_(false) {}
  ~XChaCha20Poly1305Cipher();

  void init(const std::shared_ptr<ArrayBuffer> cipher_key, const std::shared_ptr<ArrayBuffer> iv) override;
  std::shared_ptr<ArrayBuffer> update(const std::shared_ptr<ArrayBuffer>& data) override;
  std::shared_ptr<ArrayBuffer> final() override;
  bool setAAD(const std::shared_ptr<ArrayBuffer>& data, std::optional<double> plaintextLength) override;
  std::shared_ptr<ArrayBuffer> getAuthTag() override;
  bool setAuthTag(const std::shared_ptr<ArrayBuffer>& tag) override;

 private:
  static constexpr size_t kKeySize = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
  static constexpr size_t kNonceSize = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
  static constexpr size_t kTagSize = crypto_aead_xchacha20poly1305_ietf_ABYTES;

  uint8_t key_[kKeySize];
  uint8_t nonce_[kNonceSize];
  std::vector<uint8_t> aad_;
  std::vector<uint8_t> data_buffer_;
  uint8_t auth_tag_[kTagSize];
  bool final_called_;
};

} // namespace margelo::nitro::crypto
