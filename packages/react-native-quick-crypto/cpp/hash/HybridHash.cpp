#include <NitroModules/ArrayBuffer.hpp>
#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <optional>
#include <string>
#include <vector>

#include "HybridHash.hpp"
#include "Utils.hpp"

namespace margelo::nitro::crypto {

HybridHash::~HybridHash() {
  if (ctx) {
    EVP_MD_CTX_free(ctx);
    ctx = nullptr;
  }
  if (md && md_fetched) {
    EVP_MD_free(md);
    md = nullptr;
  }
}

void HybridHash::createHash(const std::string& hashAlgorithmArg, const std::optional<double> outputLengthArg) {
  // Clear any previous OpenSSL errors to prevent pollution
  clearOpenSSLErrors();
  
  // Clean up existing resources before creating new ones
  if (ctx) {
    EVP_MD_CTX_free(ctx);
    ctx = nullptr;
  }
  if (md && md_fetched) {
    EVP_MD_free(md);
    md = nullptr;
    md_fetched = false;
  }

  algorithm = hashAlgorithmArg;
  outputLength = outputLengthArg;

  // Create hash context
  ctx = EVP_MD_CTX_new();
  if (!ctx) {
    throw std::runtime_error("Failed to create hash context: " + std::to_string(ERR_get_error()));
  }

  // Fetch the message digest using modern provider-based API
  md = EVP_MD_fetch(nullptr, algorithm.c_str(), nullptr);
  if (!md) {
    EVP_MD_CTX_free(ctx);
    ctx = nullptr;
    throw std::runtime_error("Unknown hash algorithm: " + algorithm);
  }
  md_fetched = true;

  // Initialize the digest
  if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
    EVP_MD_CTX_free(ctx);
    ctx = nullptr;
    if (md_fetched) {
      EVP_MD_free(md);
      md = nullptr;
      md_fetched = false;
    }
    throw std::runtime_error("Failed to initialize hash digest: " + std::to_string(ERR_get_error()));
  }
}

void HybridHash::update(const std::shared_ptr<ArrayBuffer>& data) {
  if (!ctx) {
    throw std::runtime_error("Hash context not initialized");
  }

  // Update the digest with the data
  if (EVP_DigestUpdate(ctx, reinterpret_cast<const uint8_t*>(data->data()), data->size()) != 1) {
    throw std::runtime_error("Failed to update hash digest: " + std::to_string(ERR_get_error()));
  }
}

std::shared_ptr<ArrayBuffer> HybridHash::digest(const std::optional<std::string>& encoding) {
  if (!ctx) {
    throw std::runtime_error("Hash context not initialized");
  }

  setParams();

  // Get the default digest size
  const size_t defaultLen = EVP_MD_CTX_size(ctx);
  const size_t digestSize = (outputLength.has_value()) ? static_cast<int>(*outputLength) : defaultLen;

  if (digestSize < 0) {
    throw std::runtime_error("Invalid digest size: " + std::to_string(digestSize));
  }

  // Create a buffer for the hash output
  uint8_t* hashBuffer = new uint8_t[digestSize];
  size_t hashLength = digestSize;

  // Finalize the digest
  int ret;
  if (digestSize == defaultLen) {
    ret = EVP_DigestFinal_ex(ctx, hashBuffer, reinterpret_cast<unsigned int*>(&hashLength));
  } else {
    ret = EVP_DigestFinalXOF(ctx, hashBuffer, hashLength);
  }

  if (ret != 1) {
    delete[] hashBuffer;
    throw std::runtime_error("Failed to finalize hash digest: " + std::to_string(ERR_get_error()));
  }

  return std::make_shared<NativeArrayBuffer>(hashBuffer, hashLength, [=]() { delete[] hashBuffer; });
}

std::shared_ptr<margelo::nitro::crypto::HybridHashSpec> HybridHash::copy(const std::optional<double> outputLengthArg) {
  if (!ctx) {
    throw std::runtime_error("Hash context not initialized");
  }

  // Create a new context
  EVP_MD_CTX* newCtx = EVP_MD_CTX_new();
  if (!newCtx) {
    throw std::runtime_error("Failed to create new hash context: " + std::to_string(ERR_get_error()));
  }

  // Copy the existing context to the new one
  if (EVP_MD_CTX_copy(newCtx, ctx) != 1) {
    EVP_MD_CTX_free(newCtx);
    throw std::runtime_error("Failed to copy hash context: " + std::to_string(ERR_get_error()));
  }

  return std::make_shared<HybridHash>(newCtx, md, algorithm, outputLengthArg, false);
}

std::vector<std::string> HybridHash::getSupportedHashAlgorithms() {
  std::vector<std::string> hashAlgorithms;

  EVP_MD_do_all_provided(
      nullptr,
      [](EVP_MD* md, void* arg) {
        auto* algorithms = static_cast<std::vector<std::string>*>(arg);
        const char* name = EVP_MD_get0_name(md);
        if (name) {
          algorithms->push_back(name);
        }
      },
      &hashAlgorithms);

  return hashAlgorithms;
}

void HybridHash::setParams() {
  // Handle algorithm parameters (like XOF length for SHAKE)
  if (outputLength.has_value()) {
    uint32_t xoflen = outputLength.value();

    // Add a reasonable maximum output length
    const int MAX_OUTPUT_LENGTH = 16 * 1024 * 1024; // 16MB
    if (xoflen > MAX_OUTPUT_LENGTH) {
      throw std::runtime_error("Output length " + std::to_string(xoflen) + " exceeds maximum allowed size of " +
                               std::to_string(MAX_OUTPUT_LENGTH));
    }

    OSSL_PARAM params[] = {OSSL_PARAM_construct_uint("xoflen", &xoflen), OSSL_PARAM_END};

    if (EVP_MD_CTX_set_params(ctx, params) != 1) {
      EVP_MD_CTX_free(ctx);
      ctx = nullptr;
      if (md && md_fetched) {
        EVP_MD_free(md);
        md = nullptr;
        md_fetched = false;
      }
      throw std::runtime_error("Failed to set XOF length (outputLength) parameter: " + std::to_string(ERR_get_error()));
    }
  }
}

std::string HybridHash::getOpenSSLVersion() {
  return OpenSSL_version(OPENSSL_VERSION);
}

} // namespace margelo::nitro::crypto
