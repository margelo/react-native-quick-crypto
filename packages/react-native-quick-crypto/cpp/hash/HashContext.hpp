#pragma once

#include <openssl/err.h>
#include <openssl/evp.h>

#include <memory>
#include <stdexcept>
#include <string>

namespace margelo::quickcrypto {

using DigestContext = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

inline DigestContext createDigestContext(const std::string& algorithm) {
  ERR_clear_error();
  if (algorithm.find('\0') != std::string::npos) {
    throw std::invalid_argument("Invalid hash algorithm");
  }
  std::unique_ptr<EVP_MD, decltype(&EVP_MD_free)> md(EVP_MD_fetch(nullptr, algorithm.c_str(), nullptr), EVP_MD_free);
  if (!md) {
    throw std::invalid_argument("Unknown hash algorithm: " + algorithm);
  }
  DigestContext ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!ctx || EVP_DigestInit_ex(ctx.get(), md.get(), nullptr) != 1) {
    throw std::runtime_error("Failed to initialize hash: " + std::to_string(ERR_get_error()));
  }
  return ctx;
}

inline void updateDigest(EVP_MD_CTX* ctx, const void* data, size_t size) {
  if (EVP_DigestUpdate(ctx, data, size) != 1) {
    throw std::runtime_error("Failed to update hash: " + std::to_string(ERR_get_error()));
  }
}

inline unsigned int finishDigest(EVP_MD_CTX* ctx, unsigned char* output) {
  unsigned int written;
  if (EVP_DigestFinal_ex(ctx, output, &written) != 1) {
    throw std::runtime_error("Failed to finalize hash: " + std::to_string(ERR_get_error()));
  }
  return written;
}

} // namespace margelo::quickcrypto
