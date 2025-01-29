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

  // TODO: maybe just change the return type to void here?

  // Mock a 32 byte hash output
  uint8_t* mockHash = new uint8_t[32];
  for (int i = 0; i < 32; i++) {
    mockHash[i] = i;
  }

  return std::make_shared<NativeArrayBuffer>(
    mockHash, 32, [=]() { delete[] mockHash; });
}

void
HybridHash::update(const std::shared_ptr<ArrayBuffer>& data)
{
  if (!ctx) {
    throw std::runtime_error("Hash context not initialized");
  }

  // Update the digest with the data
  if (EVP_DigestUpdate(ctx,
                       reinterpret_cast<const unsigned char*>(data->data()),
                       data->size()) != 1) {
    throw std::runtime_error("Failed to update hash digest");
  }
}

std::string
HybridHash::digest(const std::optional<std::string>& encoding)
{
  if (!ctx) {
    throw std::runtime_error("Hash context not initialized");
  }
  
  // Get the size of the digest
  const int digestSize = EVP_MD_get_size(md);
  if (digestSize <= 0) {
    throw std::runtime_error("Invalid digest size");
  }
  
  // Create a buffer for the hash output and length
  std::vector<unsigned char> hashBuffer(digestSize);
  unsigned int hashLength = 0;
  
  // TODO: create ctx copy here to keep the original intact?
  
  // Finalize the digest
  if (EVP_DigestFinal_ex(ctx, hashBuffer.data(), &hashLength) != 1) {
    throw std::runtime_error("Failed to finalize hash digest");
  }
  
  //  TODO: implement other encodings, just doing HEX for now...
  
  // Convert to hex string
  std::string result;
  result.reserve(hashLength * 2);
  static const char hex[] = "0123456789abcdef";
  
  for (unsigned int i = 0; i < hashLength; i++) {
    result.push_back(hex[hashBuffer[i] >> 4]);
    result.push_back(hex[hashBuffer[i] & 0xF]);
  }

  return result;
}

} // namespace margelo::nitro::crypto
