#pragma once

#include <string>
#include <memory>
#include <openssl/evp.h>

#include "HybridCipherFactorySpec.hpp"
#include "CCMCipher.hpp"

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
      case EVP_CIPH_CCM_MODE: {
        cipherInstance = std::make_shared<CCMCipher>();
        break;
      }
      // Add other modes as they are implemented
      default: {
        // For all other modes, use the base HybridCipher
        cipherInstance = std::make_shared<HybridCipher>();
        break;
      }
    }
    cipherInstance->setArgs(args);
    cipherInstance->init(args.cipherKey, args.iv);
    return cipherInstance;
  }
};

} // namespace margelo::nitro::crypto
