#pragma once

#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include "HybridCipher.hpp"

namespace margelo::nitro::crypto {

class CCMCipher : public HybridCipher {
 public:
  CCMCipher() : HybridObject(TAG) {}
  ~CCMCipher() {
    // Let parent destructor free the context
    ctx = nullptr;
  }

  bool setAuthTag(const std::shared_ptr<ArrayBuffer>& tag) override;
  std::shared_ptr<ArrayBuffer> final() override;
  void setArgs(const CipherArgs& args) override;
  bool setAAD(const std::shared_ptr<ArrayBuffer>& data, std::optional<double> plaintextLength) override;
  std::shared_ptr<ArrayBuffer> update(const std::shared_ptr<ArrayBuffer>& data) override;

 private:
  // CCM mode supports messages up to 2^(8L) - 1 bytes where L is the length of nonce
  // With a 12-byte nonce (L=3), max size is 2^24 - 1 bytes
  static constexpr int kMaxMessageSize = (1 << 24) - 1;
};

}  // namespace margelo::nitro::crypto
