#include <NitroModules/ArrayBuffer.hpp>
#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <optional>
#include <string>
#include <vector>

#include "HybridHash.hpp"

namespace margelo::nitro::crypto {

void HybridHash::createHash(const std::string& hashAlgorithmArg, const std::optional<double> outputLengthArg) {
  ctx.reset();
  ctx = ::margelo::quickcrypto::createDigestContext(hashAlgorithmArg);
  outputLength = outputLengthArg;
}

void HybridHash::update(const std::variant<std::shared_ptr<ArrayBuffer>, std::string>& data) {
  if (!ctx) {
    throw std::runtime_error("Hash context not initialized");
  }

  if (std::holds_alternative<std::string>(data)) {
    const std::string& str = std::get<std::string>(data);
    ::margelo::quickcrypto::updateDigest(ctx.get(), str.data(), str.size());
  } else {
    const std::shared_ptr<ArrayBuffer>& buffer = std::get<std::shared_ptr<ArrayBuffer>>(data);
    ::margelo::quickcrypto::updateDigest(ctx.get(), buffer->data(), buffer->size());
  }
}

std::shared_ptr<ArrayBuffer> HybridHash::digest(const std::optional<std::string>& encoding) {
  if (!ctx) {
    throw std::runtime_error("Hash context not initialized");
  }

  setParams();

  // Get the default digest size
  const size_t defaultLen = EVP_MD_CTX_size(ctx.get());
  const size_t digestSize = (outputLength.has_value()) ? static_cast<int>(*outputLength) : defaultLen;

  if (digestSize < 0) {
    throw std::runtime_error("Invalid digest size: " + std::to_string(digestSize));
  }

  auto hashBuffer = std::make_unique<uint8_t[]>(digestSize);
  size_t hashLength = digestSize;

  if (digestSize == defaultLen) {
    hashLength = ::margelo::quickcrypto::finishDigest(ctx.get(), hashBuffer.get());
  } else if (EVP_DigestFinalXOF(ctx.get(), hashBuffer.get(), hashLength) != 1) {
    throw std::runtime_error("Failed to finalize hash digest: " + std::to_string(ERR_get_error()));
  }

  uint8_t* raw_ptr = hashBuffer.get();
  return std::make_shared<NativeArrayBuffer>(hashBuffer.release(), hashLength, [raw_ptr]() { delete[] raw_ptr; });
}

std::shared_ptr<margelo::nitro::crypto::HybridHashSpec> HybridHash::copy(const std::optional<double> outputLengthArg) {
  if (!ctx) {
    throw std::runtime_error("Hash context not initialized");
  }

  // Create a new context
  ::margelo::quickcrypto::DigestContext newCtx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!newCtx) {
    throw std::runtime_error("Failed to create new hash context: " + std::to_string(ERR_get_error()));
  }

  // Copy the existing context to the new one
  if (EVP_MD_CTX_copy(newCtx.get(), ctx.get()) != 1) {
    throw std::runtime_error("Failed to copy hash context: " + std::to_string(ERR_get_error()));
  }

  return std::make_shared<HybridHash>(std::move(newCtx), outputLengthArg);
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

    if (EVP_MD_CTX_set_params(ctx.get(), params) != 1) {
      ctx.reset();
      throw std::runtime_error("Failed to set XOF length (outputLength) parameter: " + std::to_string(ERR_get_error()));
    }
  }
}

std::string HybridHash::getOpenSSLVersion() {
  return OpenSSL_version(OPENSSL_VERSION);
}

} // namespace margelo::nitro::crypto
