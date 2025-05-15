#pragma once

#if BLSALLOC_SODIUM
#include "sodium.h"
#else
// Define XSalsa20 constants when sodium is disabled (for compilation purposes)
#define crypto_stream_KEYBYTES 32   // XSalsa20 key size (32 bytes)
#define crypto_stream_NONCEBYTES 24 // XSalsa20 nonce size (24 bytes)
#endif

#include "HybridCipher.hpp"
#include "NitroModules/ArrayBuffer.hpp"

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