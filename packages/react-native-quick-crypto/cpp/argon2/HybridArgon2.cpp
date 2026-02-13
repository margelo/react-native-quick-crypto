#include <NitroModules/ArrayBuffer.hpp>
#include <memory>
#include <ncrypto.h>
#include <openssl/opensslv.h>
#include <string>

#include "HybridArgon2.hpp"
#include "QuickCryptoUtils.hpp"

namespace margelo::nitro::crypto {

#if OPENSSL_VERSION_NUMBER >= 0x30200000L
#ifndef OPENSSL_NO_ARGON2

static ncrypto::Argon2Type parseAlgorithm(const std::string& algo) {
  if (algo == "argon2d") return ncrypto::Argon2Type::ARGON2D;
  if (algo == "argon2i") return ncrypto::Argon2Type::ARGON2I;
  if (algo == "argon2id") return ncrypto::Argon2Type::ARGON2ID;
  throw std::runtime_error("Unknown argon2 algorithm: " + algo);
}

static std::shared_ptr<ArrayBuffer> hashImpl(
    const std::string& algorithm,
    const std::shared_ptr<ArrayBuffer>& message,
    const std::shared_ptr<ArrayBuffer>& nonce,
    double parallelism, double tagLength, double memory,
    double passes, double version,
    const std::optional<std::shared_ptr<ArrayBuffer>>& secret,
    const std::optional<std::shared_ptr<ArrayBuffer>>& associatedData) {

  auto type = parseAlgorithm(algorithm);

  ncrypto::Buffer<const char> passBuf{
      message->size() > 0 ? reinterpret_cast<const char*>(message->data()) : "",
      message->size()};

  ncrypto::Buffer<const unsigned char> saltBuf{
      nonce->size() > 0 ? reinterpret_cast<const unsigned char*>(nonce->data()) : reinterpret_cast<const unsigned char*>(""),
      nonce->size()};

  ncrypto::Buffer<const unsigned char> secretBuf{nullptr, 0};
  if (secret.has_value() && secret.value()->size() > 0) {
    secretBuf = {reinterpret_cast<const unsigned char*>(secret.value()->data()),
                 secret.value()->size()};
  }

  ncrypto::Buffer<const unsigned char> adBuf{nullptr, 0};
  if (associatedData.has_value() && associatedData.value()->size() > 0) {
    adBuf = {reinterpret_cast<const unsigned char*>(associatedData.value()->data()),
             associatedData.value()->size()};
  }

  auto result = ncrypto::argon2(
      passBuf, saltBuf,
      static_cast<uint32_t>(parallelism),
      static_cast<size_t>(tagLength),
      static_cast<uint32_t>(memory),
      static_cast<uint32_t>(passes),
      static_cast<uint32_t>(version),
      secretBuf, adBuf, type);

  if (!result) {
    throw std::runtime_error("Argon2 operation failed");
  }

  return ToNativeArrayBuffer(
      reinterpret_cast<const uint8_t*>(result.get()), result.size());
}

#endif // OPENSSL_NO_ARGON2
#endif // OPENSSL_VERSION_NUMBER

std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>> HybridArgon2::hash(
    const std::string& algorithm,
    const std::shared_ptr<ArrayBuffer>& message,
    const std::shared_ptr<ArrayBuffer>& nonce,
    double parallelism, double tagLength, double memory,
    double passes, double version,
    const std::optional<std::shared_ptr<ArrayBuffer>>& secret,
    const std::optional<std::shared_ptr<ArrayBuffer>>& associatedData) {
#if OPENSSL_VERSION_NUMBER >= 0x30200000L && !defined(OPENSSL_NO_ARGON2)
  auto nativeMessage = ToNativeArrayBuffer(message);
  auto nativeNonce = ToNativeArrayBuffer(nonce);
  std::optional<std::shared_ptr<ArrayBuffer>> nativeSecret;
  if (secret.has_value()) {
    nativeSecret = ToNativeArrayBuffer(secret.value());
  }
  std::optional<std::shared_ptr<ArrayBuffer>> nativeAd;
  if (associatedData.has_value()) {
    nativeAd = ToNativeArrayBuffer(associatedData.value());
  }

  return Promise<std::shared_ptr<ArrayBuffer>>::async(
      [algorithm, nativeMessage, nativeNonce, parallelism, tagLength, memory,
       passes, version, nativeSecret = std::move(nativeSecret),
       nativeAd = std::move(nativeAd)]() {
        return hashImpl(algorithm, nativeMessage, nativeNonce, parallelism,
                        tagLength, memory, passes, version, nativeSecret,
                        nativeAd);
      });
#else
  throw std::runtime_error("Argon2 is not supported (requires OpenSSL 3.2+)");
#endif
}

std::shared_ptr<ArrayBuffer> HybridArgon2::hashSync(
    const std::string& algorithm,
    const std::shared_ptr<ArrayBuffer>& message,
    const std::shared_ptr<ArrayBuffer>& nonce,
    double parallelism, double tagLength, double memory,
    double passes, double version,
    const std::optional<std::shared_ptr<ArrayBuffer>>& secret,
    const std::optional<std::shared_ptr<ArrayBuffer>>& associatedData) {
#if OPENSSL_VERSION_NUMBER >= 0x30200000L && !defined(OPENSSL_NO_ARGON2)
  return hashImpl(algorithm, message, nonce, parallelism, tagLength,
                  memory, passes, version, secret, associatedData);
#else
  throw std::runtime_error("Argon2 is not supported (requires OpenSSL 3.2+)");
#endif
}

} // namespace margelo::nitro::crypto
