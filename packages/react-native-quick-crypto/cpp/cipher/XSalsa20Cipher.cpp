#include <cstring>   // For std::memcpy
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
}

/**
 * xsalsa20 call to sodium implementation
 */
std::shared_ptr<ArrayBuffer> XSalsa20Cipher::update(const std::shared_ptr<ArrayBuffer>& data) {
#ifndef BLSALLOC_SODIUM
  throw std::runtime_error("XSalsa20Cipher: libsodium must be enabled to use this cipher (BLSALLOC_SODIUM is not defined).");
#else
  auto native_data = ToNativeArrayBuffer(data);
  auto output = new uint8_t[native_data->size()];
  int result = crypto_stream_xor(output, native_data->data(), native_data->size(), nonce, key);
  if (result != 0) {
    throw std::runtime_error("XSalsa20Cipher: Failed to update");
  }
  return std::make_shared<NativeArrayBuffer>(output, native_data->size(), [=]() { delete[] output; });
#endif
}

/**
 * xsalsa20 does not have a final step, returns empty buffer
 */
std::shared_ptr<ArrayBuffer> XSalsa20Cipher::final() {
#ifndef BLSALLOC_SODIUM
  throw std::runtime_error("XSalsa20Cipher: libsodium must be enabled to use this cipher (BLSALLOC_SODIUM is not defined).");
#else
  return std::make_shared<NativeArrayBuffer>(nullptr, 0, nullptr);
#endif
}

} // namespace margelo::nitro::crypto
