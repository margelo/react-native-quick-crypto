#pragma once

#include <string>
#include <memory>
#include <openssl/evp.h>

#include "HybridCipherFactorySpec.hpp"
#include "CCMCipher.hpp"
#include "OCBCipher.hpp"

namespace margelo::nitro::crypto {

using namespace facebook;

class HybridCipherFactory : public HybridCipherFactorySpec {
 public:
  HybridCipherFactory() : HybridObject(TAG) {}
  ~HybridCipherFactory() = default;

 public:
  // Factory method exposed to JS
  inline std::shared_ptr<HybridCipherSpec> createCipher(const CipherArgs& args) {
    // Create a temporary cipher context to determine the mode
    EVP_CIPHER* cipher = EVP_CIPHER_fetch(nullptr, args.cipherType.c_str(), nullptr);
    if (!cipher) {
      throw std::runtime_error("Invalid cipher type: " + args.cipherType);
    }

    int mode = EVP_CIPHER_get_mode(cipher);
    EVP_CIPHER_free(cipher);

    // Create the appropriate cipher instance based on mode
    std::shared_ptr<HybridCipher> cipherInstance;
    switch (mode) {
      case EVP_CIPH_OCB_MODE: {
        cipherInstance = std::make_shared<OCBCipher>();
        cipherInstance->setArgs(args);
        // Pass tag length (default 16 if not present)
        size_t tag_len = args.authTagLen.has_value() ? static_cast<size_t>(args.authTagLen.value()) : 16;
        std::static_pointer_cast<OCBCipher>(cipherInstance)->init(args.cipherKey, args.iv, tag_len);
        return cipherInstance;
      }
      case EVP_CIPH_CCM_MODE: {
        cipherInstance = std::make_shared<CCMCipher>();
        cipherInstance->setArgs(args);
        cipherInstance->init(args.cipherKey, args.iv);
        return cipherInstance;
      }
      default: {
        cipherInstance = std::make_shared<HybridCipher>();
        cipherInstance->setArgs(args);
        cipherInstance->init(args.cipherKey, args.iv);
        return cipherInstance;
      }
    }
  }
};

} // namespace margelo::nitro::crypto
