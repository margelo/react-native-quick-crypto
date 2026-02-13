#include "HybridCertificate.hpp"
#include "QuickCryptoUtils.hpp"
#include <ncrypto.h>
#include <openssl/crypto.h>

namespace margelo::nitro::crypto {

bool HybridCertificate::verifySpkac(const std::shared_ptr<ArrayBuffer>& spkac) {
  return ncrypto::VerifySpkac(
    reinterpret_cast<const char*>(spkac->data()),
    spkac->size());
}

std::shared_ptr<ArrayBuffer> HybridCertificate::exportPublicKey(const std::shared_ptr<ArrayBuffer>& spkac) {
  auto bio = ncrypto::ExportPublicKey(
    reinterpret_cast<const char*>(spkac->data()),
    spkac->size());

  if (!bio) {
    return std::make_shared<NativeArrayBuffer>(nullptr, 0, nullptr);
  }

  BUF_MEM* mem = bio;
  if (!mem || mem->length == 0) {
    return std::make_shared<NativeArrayBuffer>(nullptr, 0, nullptr);
  }

  return ToNativeArrayBuffer(
    reinterpret_cast<const uint8_t*>(mem->data), mem->length);
}

std::shared_ptr<ArrayBuffer> HybridCertificate::exportChallenge(const std::shared_ptr<ArrayBuffer>& spkac) {
  auto buf = ncrypto::ExportChallenge(
    reinterpret_cast<const char*>(spkac->data()),
    spkac->size());

  if (buf.data == nullptr) {
    return std::make_shared<NativeArrayBuffer>(nullptr, 0, nullptr);
  }

  auto result = ToNativeArrayBuffer(
    reinterpret_cast<const uint8_t*>(buf.data), buf.len);
  OPENSSL_free(buf.data);
  return result;
}

} // namespace margelo::nitro::crypto
