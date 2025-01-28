#include <NitroModules/ArrayBuffer.hpp>
#include <OpenSSL/evp.h>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "HybridHash.hpp"

namespace margelo::nitro::crypto {

HybridHash::~HybridHash()
{
  if (ctx) {
    EVP_MD_CTX_free(ctx);
    ctx = nullptr;
  }
}

std::shared_ptr<ArrayBuffer>
HybridHash::createHash(const std::string& hashAlgorithm)
{
  algorithm = hashAlgorithm;

  // Create hash context
  ctx = EVP_MD_CTX_new();
  if (!ctx) {
    throw std::runtime_error("Failed to create hash context");
  }

  // Get the message digest by name
  md = EVP_get_digestbyname(algorithm.c_str());
  if (!md) {
    EVP_MD_CTX_free(ctx);
    ctx = nullptr;
    throw std::runtime_error("Unknown hash algorithm: " + algorithm);
  }

  // Initialize the digest
  if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
    EVP_MD_CTX_free(ctx);
    ctx = nullptr;
    throw std::runtime_error("Failed to initialize hash digest");
  }

  // Mock a 32 byte hash output
  uint8_t* mockHash = new uint8_t[32];
  for (int i = 0; i < 32; i++) {
    mockHash[i] = i;
  }

  return std::make_shared<NativeArrayBuffer>(
    mockHash, 32, [=]() { delete[] mockHash; });
}

void
HybridHash::update()
{
  // TODO
}

void
HybridHash::digest()
{
  // TODO
}

} // namespace margelo::nitro::crypto
