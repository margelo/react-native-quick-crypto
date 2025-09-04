#pragma once

#include <memory>
#include <openssl/evp.h>
#include <string>

#include "CCMCipher.hpp"
#include "ChaCha20Cipher.hpp"
#include "ChaCha20Poly1305Cipher.hpp"
#include "HybridCipherFactorySpec.hpp"
#include "OCBCipher.hpp"
#include "Utils.hpp"
#include "XSalsa20Cipher.hpp"

namespace margelo::nitro::crypto {

using namespace facebook;

class HybridCipherFactory : public HybridCipherFactorySpec {
 public:
  HybridCipherFactory() : HybridObject(TAG) {}
  ~HybridCipherFactory() = default;

 public:
  // Factory method exposed to JS
  inline std::shared_ptr<HybridCipherSpec> createCipher(const CipherArgs& args) {
    // Create the appropriate cipher instance based on mode
    std::shared_ptr<HybridCipher> cipherInstance;

    // OpenSSL
    // temporary cipher context to determine the mode
    EVP_CIPHER* cipher = EVP_CIPHER_fetch(nullptr, args.cipherType.c_str(), nullptr);
    if (cipher) {
      int mode = EVP_CIPHER_get_mode(cipher);

      switch (mode) {
        case EVP_CIPH_OCB_MODE: {
          cipherInstance = std::make_shared<OCBCipher>();
          cipherInstance->setArgs(args);
          // Pass tag length (default 16 if not present)
          size_t tag_len = args.authTagLen.has_value() ? static_cast<size_t>(args.authTagLen.value()) : 16;
          std::static_pointer_cast<OCBCipher>(cipherInstance)->init(args.cipherKey, args.iv, tag_len);
          EVP_CIPHER_free(cipher);
          return cipherInstance;
        }
        case EVP_CIPH_CCM_MODE: {
          cipherInstance = std::make_shared<CCMCipher>();
          cipherInstance->setArgs(args);
          cipherInstance->init(args.cipherKey, args.iv);
          EVP_CIPHER_free(cipher);
          return cipherInstance;
        }
        case EVP_CIPH_STREAM_CIPHER: {
          // Check for ChaCha20 variants specifically
          std::string cipherName = toLower(args.cipherType);
          if (cipherName == "chacha20") {
            cipherInstance = std::make_shared<ChaCha20Cipher>();
            cipherInstance->setArgs(args);
            cipherInstance->init(args.cipherKey, args.iv);
            EVP_CIPHER_free(cipher);
            return cipherInstance;
          }
          if (cipherName == "chacha20-poly1305") {
            cipherInstance = std::make_shared<ChaCha20Poly1305Cipher>();
            cipherInstance->setArgs(args);
            cipherInstance->init(args.cipherKey, args.iv);
            EVP_CIPHER_free(cipher);
            return cipherInstance;
          }
        }
        default: {
          // Default case for other ciphers
          cipherInstance = std::make_shared<HybridCipher>();
          cipherInstance->setArgs(args);
          cipherInstance->init(args.cipherKey, args.iv);
          EVP_CIPHER_free(cipher);
          return cipherInstance;
        }
      }
    }
    EVP_CIPHER_free(cipher);

    // libsodium
    std::string cipherName = toLower(args.cipherType);
    if (cipherName == "xsalsa20") {
      cipherInstance = std::make_shared<XSalsa20Cipher>();
      cipherInstance->setArgs(args);
      cipherInstance->init(args.cipherKey, args.iv);
      return cipherInstance;
    }

    // Unsupported cipher type
    throw std::runtime_error("Unsupported or unknown cipher type: " + args.cipherType);
  }
};

} // namespace margelo::nitro::crypto
