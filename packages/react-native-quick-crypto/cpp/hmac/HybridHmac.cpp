#include <NitroModules/ArrayBuffer.hpp>
#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <optional>
#include <string>
#include <vector>

#include "HybridHmac.hpp"

namespace margelo::nitro::crypto {

HybridHmac::~HybridHmac() {
  if (ctx) {
    EVP_MAC_CTX_free(ctx);
    ctx = nullptr;
  }
}

void HybridHmac::createHmac(const std::string& hmacAlgorithm, const std::shared_ptr<ArrayBuffer>& secretKey) {
  algorithm = hmacAlgorithm;

  // Create and use EVP_MAC locally
  EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
  if (!mac) {
    throw std::runtime_error("Failed to fetch HMAC implementation: " + std::to_string(ERR_get_error()));
  }

  // Create HMAC context
  ctx = EVP_MAC_CTX_new(mac);
  EVP_MAC_free(mac); // Free immediately after creating the context
  if (!ctx) {
    throw std::runtime_error("Failed to create HMAC context: " + std::to_string(ERR_get_error()));
  }

  // Validate algorithm
  const EVP_MD* md = EVP_get_digestbyname(algorithm.c_str());
  if (!md) {
    throw std::runtime_error("Unknown HMAC algorithm: " + algorithm);
  }

  // Set up parameters for HMAC
  OSSL_PARAM params[2];
  params[0] = OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>(algorithm.c_str()), 0);
  params[1] = OSSL_PARAM_construct_end();

  const uint8_t* keyData = reinterpret_cast<const uint8_t*>(secretKey->data());
  size_t keySize = secretKey->size();

  // Handle empty key case by providing a dummy key
  static const uint8_t dummyKey = 0;
  if (keySize == 0) {
    keyData = &dummyKey;
    keySize = 1;
  }

  // Initialize HMAC
  if (EVP_MAC_init(ctx, keyData, keySize, params) != 1) {
    throw std::runtime_error("Failed to initialize HMAC: " + std::to_string(ERR_get_error()));
  }
}

void HybridHmac::update(const std::variant<std::shared_ptr<ArrayBuffer>, std::string>& data) {
  if (!ctx) {
    throw std::runtime_error("HMAC context not initialized");
  }

  if (std::holds_alternative<std::string>(data)) {
    // Handle string: pass UTF-8 bytes directly to OpenSSL
    const std::string& str = std::get<std::string>(data);
    if (EVP_MAC_update(ctx, reinterpret_cast<const uint8_t*>(str.data()), str.length()) != 1) {
      throw std::runtime_error("Failed to update HMAC: " + std::to_string(ERR_get_error()));
    }
  } else {
    // Handle ArrayBuffer
    const std::shared_ptr<ArrayBuffer>& buffer = std::get<std::shared_ptr<ArrayBuffer>>(data);
    if (EVP_MAC_update(ctx, reinterpret_cast<const uint8_t*>(buffer->data()), buffer->size()) != 1) {
      throw std::runtime_error("Failed to update HMAC: " + std::to_string(ERR_get_error()));
    }
  }
}

std::shared_ptr<ArrayBuffer> HybridHmac::digest() {
  if (!ctx) {
    throw std::runtime_error("HMAC context not initialized");
  }

  // Determine the maximum possible size of the HMAC output
  const EVP_MD* md = EVP_get_digestbyname(algorithm.c_str());
  const size_t hmacLength = EVP_MD_get_size(md);

  // Allocate buffer with the exact required size
  uint8_t* hmacBuffer = new uint8_t[hmacLength];

  // Finalize the HMAC computation directly into the final buffer
  if (EVP_MAC_final(ctx, hmacBuffer, nullptr, hmacLength) != 1) {
    delete[] hmacBuffer;
    throw std::runtime_error("Failed to finalize HMAC digest: " + std::to_string(ERR_get_error()));
  }

  return std::make_shared<NativeArrayBuffer>(hmacBuffer, hmacLength, [=]() { delete[] hmacBuffer; });
}

} // namespace margelo::nitro::crypto
