#include "ChaCha20Cipher.hpp"
#include "Utils.hpp"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdexcept>

namespace margelo::nitro::crypto {

using namespace margelo::nitro;

// Implement virtual methods from HybridCipher
const EVP_CIPHER* ChaCha20Cipher::getCipherImpl() {
  return EVP_chacha20();
}

void ChaCha20Cipher::validateKeySize(size_t key_size) const {
  if (key_size != kKeySize) {
    throw std::runtime_error("ChaCha20 key must be 32 bytes");
  }
}

void ChaCha20Cipher::validateIVSize(size_t iv_size) const {
  if (iv_size != kIVSize) {
    throw std::runtime_error("ChaCha20 IV must be 16 bytes");
  }
}

std::string ChaCha20Cipher::getCipherName() const {
  return "ChaCha20";
}

// Use the base class implementation which now uses our virtual methods
void ChaCha20Cipher::init(const std::shared_ptr<ArrayBuffer> cipher_key, const std::shared_ptr<ArrayBuffer> iv) {
  HybridCipher::init(cipher_key, iv);
}

std::shared_ptr<ArrayBuffer> ChaCha20Cipher::update(const std::shared_ptr<ArrayBuffer>& data) {
  checkCtx();
  auto native_data = ToNativeArrayBuffer(data);
  size_t in_len = native_data->size();
  if (in_len > INT_MAX) {
    throw std::runtime_error("Message too long");
  }

  // For ChaCha20, output size equals input size since it's a stream cipher
  int out_len = in_len;
  uint8_t* out = new uint8_t[out_len];

  // Perform the cipher update operation
  if (EVP_CipherUpdate(ctx, out, &out_len, native_data->data(), in_len) != 1) {
    delete[] out;
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error("ChaCha20Cipher: Failed to update: " + std::string(err_buf));
  }

  // Create and return a new buffer of exact size needed
  return std::make_shared<NativeArrayBuffer>(out, out_len, [=]() { delete[] out; });
}

std::shared_ptr<ArrayBuffer> ChaCha20Cipher::final() {
  checkCtx();
  // For ChaCha20, final() should return an empty buffer since it's a stream cipher
  unsigned char* empty_output = new unsigned char[0];
  return std::make_shared<NativeArrayBuffer>(empty_output, 0, [=]() { delete[] empty_output; });
}

} // namespace margelo::nitro::crypto
