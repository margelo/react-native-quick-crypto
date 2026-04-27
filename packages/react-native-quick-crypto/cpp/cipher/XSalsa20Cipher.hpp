#pragma once

#if BLSALLOC_SODIUM
#include "sodium.h"
#else
// Define XSalsa20 constants when sodium is disabled (for compilation purposes)
#define crypto_stream_KEYBYTES 32   // XSalsa20 key size (32 bytes)
#define crypto_stream_NONCEBYTES 24 // XSalsa20 nonce size (24 bytes)
#endif

#include <cstddef>
#include <cstdint>

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
  // Salsa20 (and therefore XSalsa20) processes the keystream in 64-byte blocks.
  static constexpr std::size_t kSalsa20BlockBytes = 64;

  uint8_t key[crypto_stream_KEYBYTES];
  uint8_t nonce[crypto_stream_NONCEBYTES];

  // Streaming state — keeps the keystream advancing across multiple update()
  // calls. Without this, every update() would restart at block 0, producing
  // identical keystream for each chunk (a two-time-pad break).
  uint8_t leftover_keystream[kSalsa20BlockBytes] = {};
  // 0..kSalsa20BlockBytes; the sentinel value kSalsa20BlockBytes means "no
  // leftover keystream available — start the next chunk on a block boundary".
  std::size_t leftover_offset = kSalsa20BlockBytes;
  // Index of the next 64-byte keystream block to consume.
  uint64_t block_counter = 0;
};

} // namespace margelo::nitro::crypto
