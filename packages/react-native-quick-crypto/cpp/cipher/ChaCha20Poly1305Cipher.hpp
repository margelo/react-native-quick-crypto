#pragma once

#include "HybridCipher.hpp"

namespace margelo::nitro::crypto {

class ChaCha20Poly1305Cipher : public HybridCipher {
 public:
  ChaCha20Poly1305Cipher() : HybridObject(TAG), final_called(false) {}
  ~ChaCha20Poly1305Cipher() {
    // Let parent destructor free the context
    ctx = nullptr;
  }

  void init(const std::shared_ptr<ArrayBuffer> cipher_key, const std::shared_ptr<ArrayBuffer> iv) override;
  std::shared_ptr<ArrayBuffer> update(const std::shared_ptr<ArrayBuffer>& data) override;
  std::shared_ptr<ArrayBuffer> final() override;
  bool setAAD(const std::shared_ptr<ArrayBuffer>& data, std::optional<double> plaintextLength) override;
  std::shared_ptr<ArrayBuffer> getAuthTag() override;
  bool setAuthTag(const std::shared_ptr<ArrayBuffer>& tag) override;

 private:
  // ChaCha20-Poly1305 uses a 256-bit key (32 bytes) and a 96-bit nonce (12 bytes)
  static constexpr int kKeySize = 32;
  static constexpr int kNonceSize = 12;
  static constexpr int kTagSize = 16; // Poly1305 tag is always 16 bytes
  bool final_called;
};

} // namespace margelo::nitro::crypto
