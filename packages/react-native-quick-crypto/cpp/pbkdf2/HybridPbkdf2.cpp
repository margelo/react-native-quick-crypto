#include "HybridPbkdf2.hpp"
#include "Utils.hpp"

namespace margelo::nitro::crypto {

std::future<std::shared_ptr<ArrayBuffer>>
HybridPbkdf2::pbkdf2(
  const std::shared_ptr<ArrayBuffer>& password,
  const std::shared_ptr<ArrayBuffer>& salt,
  double iterations,
  double keylen,
  const std::string& digest
) {
  // get owned NativeArrayBuffers before passing to sync function
  auto nativePassword = ToNativeArrayBuffer(password);
  auto nativeSalt = ToNativeArrayBuffer(salt);

  return std::async(std::launch::async,
                    [this, nativePassword, nativeSalt, iterations, keylen, digest]() {
                      return this->pbkdf2Sync(nativePassword, nativeSalt, iterations, keylen, digest);
                    });
}

std::shared_ptr<ArrayBuffer>
HybridPbkdf2::pbkdf2Sync(
  const std::shared_ptr<ArrayBuffer>& password,
  const std::shared_ptr<ArrayBuffer>& salt,
  double iterations,
  double keylen,
  const std::string& digest
) {
    size_t bufferSize = static_cast<size_t>(keylen);
    uint8_t* data = new uint8_t[bufferSize];
    auto result = std::make_shared<NativeArrayBuffer>(data, bufferSize, [=]() { delete[] data; });

    // use fastpbkdf2 when possible
    if (digest == "sha1") {
      fastpbkdf2_hmac_sha1(password.get()->data(), password.get()->size(),
                           salt.get()->data(), salt.get()->size(),
                           static_cast<uint32_t>(iterations),
                           result.get()->data(), result.get()->size());
    } else if (digest == "sha256") {
      fastpbkdf2_hmac_sha256(password.get()->data(), password.get()->size(),
                             salt.get()->data(), salt.get()->size(),
                             static_cast<uint32_t>(iterations),
                             result.get()->data(), result.get()->size());
    } else if (digest == "sha512") {
      fastpbkdf2_hmac_sha512(password.get()->data(), password.get()->size(),
                             salt.get()->data(), salt.get()->size(),
                             static_cast<uint32_t>(iterations),
                             result.get()->data(), result.get()->size());
    } else {
      // fallback to OpenSSL
      auto *digestByName = EVP_get_digestbyname(digest.c_str());
      if (digestByName == nullptr) {
        throw std::runtime_error("Invalid hash-algorithm: " + digest);
      }
      char *passAsCharA = reinterpret_cast<char *>(password.get()->data());
      const unsigned char *saltAsCharA =
          reinterpret_cast<const unsigned char *>(salt.get()->data());
      unsigned char *resultAsCharA =
          reinterpret_cast<unsigned char *>(result.get()->data());
      PKCS5_PBKDF2_HMAC(passAsCharA, password.get()->size(), saltAsCharA,
                        salt.get()->size(), static_cast<uint32_t>(iterations),
                        digestByName, result.get()->size(), resultAsCharA);
    }

    return result;
}

} // namespace margelo::nitro::crypto
