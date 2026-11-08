#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace margelo::nitro::crypto {

inline std::size_t slhDsaRawPrivateKeySize(std::string_view variant) {
  static constexpr std::array<std::pair<std::string_view, std::size_t>, 12> variants{{
      {"SLH-DSA-SHA2-128s", 64},
      {"SLH-DSA-SHA2-128f", 64},
      {"SLH-DSA-SHA2-192s", 96},
      {"SLH-DSA-SHA2-192f", 96},
      {"SLH-DSA-SHA2-256s", 128},
      {"SLH-DSA-SHA2-256f", 128},
      {"SLH-DSA-SHAKE-128s", 64},
      {"SLH-DSA-SHAKE-128f", 64},
      {"SLH-DSA-SHAKE-192s", 96},
      {"SLH-DSA-SHAKE-192f", 96},
      {"SLH-DSA-SHAKE-256s", 128},
      {"SLH-DSA-SHAKE-256f", 128},
  }};
  for (const auto& [name, size] : variants) {
    if (variant == name)
      return size;
  }
  return 0;
}

// One bounded owned secret and one queued/running validation across runtimes.
class SlhDsaRawPrivateKeyValidation final {
 public:
  SlhDsaRawPrivateKeyValidation(std::string variant, const uint8_t* input, std::size_t size)
      : variant_(std::move(variant)), size_(slhDsaRawPrivateKeySize(variant_)) {
    if (input == nullptr || size_ == 0 || size != size_ || inFlight_.test_and_set(std::memory_order_acquire))
      fail();
    std::copy_n(input, size_, secret_.begin());
  }

  ~SlhDsaRawPrivateKeyValidation() {
    OPENSSL_cleanse(secret_.data(), secret_.size());
    inFlight_.clear(std::memory_order_release);
  }

  SlhDsaRawPrivateKeyValidation(const SlhDsaRawPrivateKeyValidation&) = delete;
  SlhDsaRawPrivateKeyValidation& operator=(const SlhDsaRawPrivateKeyValidation&) = delete;

  std::vector<uint8_t> validate() const {
#if OPENSSL_VERSION_NUMBER >= 0x30600000L
    struct ErrorScope {
      ErrorScope() {
        ERR_clear_error();
      }
      ~ErrorScope() {
        ERR_clear_error();
      }
    } errors;
    using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using Context = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
    const Key key(EVP_PKEY_new_raw_private_key_ex(nullptr, variant_.c_str(), nullptr, secret_.data(), size_), EVP_PKEY_free);
    if (!key || EVP_PKEY_is_a(key.get(), variant_.c_str()) != 1)
      fail();
    const Context context(EVP_PKEY_CTX_new_from_pkey(nullptr, key.get(), nullptr), EVP_PKEY_CTX_free);
    // Raw import accepts a supplied root. The provider must verify consistency.
    if (!context || EVP_PKEY_pairwise_check(context.get()) != 1)
      fail();
    std::vector<uint8_t> publicKey(size_ / 2);
    std::size_t size = publicKey.size();
    if (EVP_PKEY_get_raw_public_key(key.get(), publicKey.data(), &size) != 1 || size != publicKey.size() ||
        CRYPTO_memcmp(publicKey.data(), secret_.data() + size_ - publicKey.size(), publicKey.size()) != 0)
      fail();
    return publicKey;
#else
    fail();
#endif
  }

 private:
  [[noreturn]] static void fail() {
    throw std::runtime_error("SLH-DSA raw private key validation failed");
  }
  inline static std::atomic_flag inFlight_ = ATOMIC_FLAG_INIT;
  std::string variant_;
  std::size_t size_;
  std::array<uint8_t, 128> secret_{};
};

} // namespace margelo::nitro::crypto
