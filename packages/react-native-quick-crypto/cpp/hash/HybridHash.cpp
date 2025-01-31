#include <NitroModules/ArrayBuffer.hpp>
#include <openssl/evp.h>
#include <memory>
#include <optional>
#include <string>

#include "HybridHash.hpp"

namespace margelo::nitro::crypto {

HybridHash::~HybridHash()
{
  if (ctx) {
    EVP_MD_CTX_free(ctx);
    ctx = nullptr;
  }
}

void
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

std::shared_ptr<ArrayBuffer>
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
  unsigned char* hashBuffer = new unsigned char[digestSize];
  unsigned int hashLength = 0;

  // Finalize the digest
  if (EVP_DigestFinal_ex(ctx, hashBuffer, &hashLength) != 1) {
    delete[] hashBuffer;
    throw std::runtime_error("Failed to finalize hash digest");
  }

  return std::make_shared<NativeArrayBuffer>(
    hashBuffer, hashLength, [=]() { delete[] hashBuffer; });
}

void
HybridHash::copy()
{
  if (!ctx) {
    throw std::runtime_error("Hash context not initialized");
  }

  // Create a new context
  EVP_MD_CTX* newCtx = EVP_MD_CTX_new();
  if (!newCtx) {
    throw std::runtime_error("Failed to create new hash context");
  }

  // Copy the existing context to the new one
  if (EVP_MD_CTX_copy(newCtx, ctx) != 1) {
    EVP_MD_CTX_free(newCtx);
    throw std::runtime_error("Failed to copy hash context");
  }

  // Replace the current context with the new one
  if (ctx) {
    EVP_MD_CTX_free(ctx);
  }
  ctx = newCtx;
}

} // namespace margelo::nitro::crypto
