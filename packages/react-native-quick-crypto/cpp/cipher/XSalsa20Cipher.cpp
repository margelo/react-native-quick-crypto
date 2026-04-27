#include <algorithm>
#include <cstring>   // For std::memcpy
#include <memory>    // For std::unique_ptr
#include <stdexcept> // For std::runtime_error

#include "NitroModules/ArrayBuffer.hpp"
#include "QuickCryptoUtils.hpp"
#include "XSalsa20Cipher.hpp"

namespace margelo::nitro::crypto {

/**
 * Initialize the cipher with a key and a nonce (using iv argument as nonce)
 */
void XSalsa20Cipher::init(const std::shared_ptr<ArrayBuffer> cipher_key, const std::shared_ptr<ArrayBuffer> iv) {
  auto native_key = ToNativeArrayBuffer(cipher_key);
  auto native_iv = ToNativeArrayBuffer(iv);

  // Validate key size
  if (native_key->size() < crypto_stream_KEYBYTES) {
    throw std::runtime_error("XSalsa20 key too short: expected " + std::to_string(crypto_stream_KEYBYTES) + " bytes, got " +
                             std::to_string(native_key->size()) + " bytes.");
  }
  // Validate nonce size
  if (native_iv->size() < crypto_stream_NONCEBYTES) {
    throw std::runtime_error("XSalsa20 nonce too short: expected " + std::to_string(crypto_stream_NONCEBYTES) + " bytes, got " +
                             std::to_string(native_iv->size()) + " bytes.");
  }

  // Copy key and nonce data
  std::memcpy(key, native_key->data(), crypto_stream_KEYBYTES);
  std::memcpy(nonce, native_iv->data(), crypto_stream_NONCEBYTES);

  // Reset streaming state so a re-init'd cipher does not accidentally reuse
  // keystream bytes from a previous session.
  block_counter = 0;
  leftover_offset = kSalsa20BlockBytes;

  is_finalized = false;
}

/**
 * xsalsa20 update — encrypts/decrypts `data` while keeping the keystream
 * advancing across successive update() calls.
 *
 * Implementation notes:
 *   1. First, drain any unused keystream bytes left over from the previous
 *      chunk's trailing partial block.
 *   2. Then process as many aligned whole 64-byte blocks as possible by
 *      jumping the keystream to `block_counter` via crypto_stream_xsalsa20_xor_ic.
 *   3. For the remaining tail (< 64 bytes), generate one full keystream
 *      block, XOR the requested prefix, and stash the unused suffix for the
 *      next update() call.
 */
std::shared_ptr<ArrayBuffer> XSalsa20Cipher::update(const std::shared_ptr<ArrayBuffer>& data) {
  checkNotFinalized();
#ifndef BLSALLOC_SODIUM
  throw std::runtime_error("XSalsa20Cipher: libsodium must be enabled to use this cipher (BLSALLOC_SODIUM is not defined).");
#else
  auto native_data = ToNativeArrayBuffer(data);
  const std::size_t data_size = native_data->size();

  if (data_size == 0) {
    return std::make_shared<NativeArrayBuffer>(nullptr, 0, nullptr);
  }

  // Owning buffer: prevents leaking `output` if we throw on the way out.
  auto output = std::make_unique<uint8_t[]>(data_size);
  const uint8_t* input = native_data->data();
  std::size_t pos = 0;

  // (1) Drain any unused keystream from the previous update()'s tail block.
  if (leftover_offset < kSalsa20BlockBytes) {
    const std::size_t avail = kSalsa20BlockBytes - leftover_offset;
    const std::size_t take = std::min(avail, data_size);
    for (std::size_t i = 0; i < take; ++i) {
      output[i] = input[i] ^ leftover_keystream[leftover_offset + i];
    }
    leftover_offset += take;
    pos = take;
  }

  // (2) Encrypt the aligned whole blocks at the current block counter.
  const std::size_t remaining = data_size - pos;
  const std::size_t whole_blocks = remaining / kSalsa20BlockBytes;
  const std::size_t whole_bytes = whole_blocks * kSalsa20BlockBytes;
  if (whole_bytes > 0) {
    int rc = crypto_stream_xsalsa20_xor_ic(output.get() + pos, input + pos, whole_bytes, nonce, block_counter, key);
    if (rc != 0) {
      throw std::runtime_error("XSalsa20Cipher: crypto_stream_xsalsa20_xor_ic failed");
    }
    block_counter += whole_blocks;
    pos += whole_bytes;
  }

  // (3) For any trailing partial block, generate one full keystream block,
  //     XOR the requested prefix, and stash the unused keystream bytes for
  //     the next update() call.
  const std::size_t tail = data_size - pos;
  if (tail > 0) {
    uint8_t zeros[kSalsa20BlockBytes] = {};
    int rc = crypto_stream_xsalsa20_xor_ic(leftover_keystream, zeros, kSalsa20BlockBytes, nonce, block_counter, key);
    if (rc != 0) {
      throw std::runtime_error("XSalsa20Cipher: crypto_stream_xsalsa20_xor_ic failed");
    }
    for (std::size_t i = 0; i < tail; ++i) {
      output[pos + i] = input[pos + i] ^ leftover_keystream[i];
    }
    leftover_offset = tail;
    block_counter += 1;
  }

  uint8_t* raw = output.release();
  return std::make_shared<NativeArrayBuffer>(raw, data_size, [=]() { delete[] raw; });
#endif
}

/**
 * xsalsa20 does not have a final step, returns empty buffer
 */
std::shared_ptr<ArrayBuffer> XSalsa20Cipher::final() {
  checkNotFinalized();
#ifndef BLSALLOC_SODIUM
  throw std::runtime_error("XSalsa20Cipher: libsodium must be enabled to use this cipher (BLSALLOC_SODIUM is not defined).");
#else
  is_finalized = true;
  return std::make_shared<NativeArrayBuffer>(nullptr, 0, nullptr);
#endif
}

} // namespace margelo::nitro::crypto
