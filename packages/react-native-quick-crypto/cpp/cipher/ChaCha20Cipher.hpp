#pragma once

#include "HybridCipher.hpp"

namespace margelo::nitro::crypto {

class ChaCha20Cipher : public HybridCipher {
 public:
  ChaCha20Cipher() : HybridObject(TAG) {}
  ~ChaCha20Cipher() {
    // Let parent destructor free the context
    ctx = nullptr;
  }

  void init(const std::shared_ptr<ArrayBuffer> cipher_key, const std::shared_ptr<ArrayBuffer> iv) override;
  std::shared_ptr<ArrayBuffer> update(const std::shared_ptr<ArrayBuffer>& data) override;
  std::shared_ptr<ArrayBuffer> final() override;

 private:
  // ChaCha20 uses a 256-bit key (32 bytes) and a 128-bit IV (16 bytes)
  static constexpr int kKeySize = 32;
  static constexpr int kIVSize = 16;
};

} // namespace margelo::nitro::crypto
