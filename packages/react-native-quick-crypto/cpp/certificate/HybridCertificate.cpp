#include "HybridCertificate.hpp"
#include "QuickCryptoUtils.hpp"
#include <ncrypto.h>
#include <openssl/crypto.h>

namespace margelo::nitro::crypto {

bool HybridCertificate::verifySpkac(const std::shared_ptr<ArrayBuffer>& spkac) {
  return ncrypto::VerifySpkac(reinterpret_cast<const char*>(spkac->data()), spkac->size());
}

std::shared_ptr<ArrayBuffer> HybridCertificate::exportPublicKey(const std::shared_ptr<ArrayBuffer>& spkac) {
  auto bio = ncrypto::ExportPublicKey(reinterpret_cast<const char*>(spkac->data()), spkac->size());

  if (!bio) {
    auto empty = new uint8_t[0];
    return std::make_shared<NativeArrayBuffer>(empty, 0, [empty]() { delete[] empty; });
  }

  BUF_MEM* mem = bio;
  if (!mem || mem->length == 0) {
    auto empty = new uint8_t[0];
    return std::make_shared<NativeArrayBuffer>(empty, 0, [empty]() { delete[] empty; });
  }

  return ToNativeArrayBuffer(reinterpret_cast<const uint8_t*>(mem->data), mem->length);
}

std::shared_ptr<ArrayBuffer> HybridCertificate::exportChallenge(const std::shared_ptr<ArrayBuffer>& spkac) {
  auto buf = ncrypto::ExportChallenge(reinterpret_cast<const char*>(spkac->data()), spkac->size());

  if (buf.data == nullptr) {
    auto empty = new uint8_t[0];
    return std::make_shared<NativeArrayBuffer>(empty, 0, [empty]() { delete[] empty; });
  }

  auto result = ToNativeArrayBuffer(reinterpret_cast<const uint8_t*>(buf.data), buf.len);
  OPENSSL_free(buf.data);
  return result;
}

} // namespace margelo::nitro::crypto
