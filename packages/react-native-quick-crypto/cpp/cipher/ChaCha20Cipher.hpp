#pragma once

#include "HybridCipher.hpp"
#include <openssl/evp.h>
#include <string>

namespace margelo::nitro::crypto {

using namespace margelo::nitro;

class ChaCha20Cipher : public HybridCipher {
 public:
  ChaCha20Cipher() : HybridCipher() {}
  ~ChaCha20Cipher() override {
    // Let parent destructor free the context
    ctx = nullptr;
  }

  void init(const std::shared_ptr<ArrayBuffer> cipher_key, const std::shared_ptr<ArrayBuffer> iv) override;
  std::shared_ptr<ArrayBuffer> update(const std::shared_ptr<ArrayBuffer>& data) override;
  std::shared_ptr<ArrayBuffer> final() override;

 protected:
  // Implement virtual methods from HybridCipher
  const EVP_CIPHER* getCipherImpl() override;
  void validateKeySize(size_t key_size) const override;
  void validateIVSize(size_t iv_size) const override;
  std::string getCipherName() const override;

 private:
  // ChaCha20 uses a 256-bit key (32 bytes) and a 128-bit IV (16 bytes)
  static constexpr int kKeySize = 32;
  static constexpr int kIVSize = 16;
};

} // namespace margelo::nitro::crypto
