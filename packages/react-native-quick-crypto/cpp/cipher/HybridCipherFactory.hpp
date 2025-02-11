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
    switch (mode) {
      case EVP_CIPH_CCM_MODE: {
        auto ccm = std::make_shared<CCMCipher>();
        ccm->setArgs(args);
        return ccm;
      }
      // Add other modes as they are implemented
      default: {
        // For all other modes, use the base HybridCipher
        auto base = std::make_shared<HybridCipher>();
        base->setArgs(args);
        return base;
      }
    }
  }
};

} // namespace margelo::nitro::crypto
