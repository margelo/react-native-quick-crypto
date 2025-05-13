#pragma once

#include "sodium.h"

#include "ArrayBuffer.hpp"
#include "HybridCipher.hpp"

namespace margelo::nitro::crypto {

class XSalsa20Cipher : public HybridCipher {
 public:
  XSalsa20Cipher() : HybridObject(TAG) {}
  ~XSalsa20Cipher() {
    // Let parent destructor free the context
    ctx = nullptr;
  }

  void init(const std::shared_ptr<ArrayBuffer> cipher_key, const std::shared_ptr<ArrayBuffer> iv) override;
  std::shared_ptr<ArrayBuffer> update(const std::shared_ptr<ArrayBuffer>& data) override;
  std::shared_ptr<ArrayBuffer> final() override;

 private:
  uint8_t key[crypto_stream_KEYBYTES];
  uint8_t nonce[crypto_stream_NONCEBYTES];
};

} // namespace margelo::nitro::crypto
