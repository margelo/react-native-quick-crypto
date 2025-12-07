#include <NitroModules/ArrayBuffer.hpp>
#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string>
#include <vector>

#include "HybridScrypt.hpp"
#include "Utils.hpp"

namespace margelo::nitro::crypto {

std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>> HybridScrypt::deriveKey(const std::shared_ptr<ArrayBuffer>& password,
                                                                               const std::shared_ptr<ArrayBuffer>& salt, double N, double r,
                                                                               double p, double maxmem, double keylen) {
  // get owned NativeArrayBuffers before passing to sync function
  auto nativePassword = ToNativeArrayBuffer(password);
  auto nativeSalt = ToNativeArrayBuffer(salt);

  return Promise<std::shared_ptr<ArrayBuffer>>::async([this, nativePassword, nativeSalt, N, r, p, maxmem, keylen]() {
    return this->deriveKeySync(nativePassword, nativeSalt, N, r, p, maxmem, keylen);
  });
}

std::shared_ptr<ArrayBuffer> HybridScrypt::deriveKeySync(const std::shared_ptr<ArrayBuffer>& password,
                                                         const std::shared_ptr<ArrayBuffer>& salt, double N, double r, double p,
                                                         double maxmem, double keylen) {
  // Use EVP_PBE_scrypt to match Node.js implementation exactly
  // All parameters are uint64_t for this API (unlike EVP_KDF which uses uint32_t for r/p)
  uint64_t n_val = static_cast<uint64_t>(N);
  uint64_t r_val = static_cast<uint64_t>(r);
  uint64_t p_val = static_cast<uint64_t>(p);
  uint64_t maxmem_val = static_cast<uint64_t>(maxmem);
  size_t outLen = static_cast<size_t>(keylen);

  if (outLen == 0) {
    throw std::runtime_error("SCRYPT length cannot be zero");
  }

  // Prepare password and salt pointers
  const char* pass_data = password && password->size() > 0 ? reinterpret_cast<const char*>(password->data()) : "";
  size_t pass_len = password ? password->size() : 0;

  const unsigned char* salt_data =
      salt && salt->size() > 0 ? reinterpret_cast<const unsigned char*>(salt->data()) : reinterpret_cast<const unsigned char*>("");
  size_t salt_len = salt ? salt->size() : 0;

  // Allocate output buffer
  uint8_t* outBuf = new uint8_t[outLen];

  // Use EVP_PBE_scrypt - the same API Node.js uses
  int result = EVP_PBE_scrypt(pass_data, pass_len, salt_data, salt_len, n_val, r_val, p_val, maxmem_val, outBuf, outLen);

  if (result != 1) {
    delete[] outBuf;
    throw std::runtime_error("SCRYPT derivation failed: " + getOpenSSLError());
  }

  return std::make_shared<NativeArrayBuffer>(outBuf, outLen, [=]() { delete[] outBuf; });
}

} // namespace margelo::nitro::crypto
