#include <NitroModules/ArrayBuffer.hpp>
#include <memory>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string>
#include <vector>

#include "HybridKmac.hpp"

namespace margelo::nitro::crypto {

HybridKmac::~HybridKmac() {
  if (ctx) {
    EVP_MAC_CTX_free(ctx);
    ctx = nullptr;
  }
}

void HybridKmac::createKmac(const std::string& algorithm, const std::shared_ptr<ArrayBuffer>& key, double outputLength,
                            const std::optional<std::shared_ptr<ArrayBuffer>>& customization) {
  outputLen = static_cast<size_t>(outputLength);
  if (outputLen == 0) {
    throw std::runtime_error("KMAC output length must be greater than 0");
  }

  EVP_MAC* mac = EVP_MAC_fetch(nullptr, algorithm.c_str(), nullptr);
  if (!mac) {
    throw std::runtime_error("Failed to fetch " + algorithm + " implementation: " + std::to_string(ERR_get_error()));
  }

  ctx = EVP_MAC_CTX_new(mac);
  EVP_MAC_free(mac);
  if (!ctx) {
    throw std::runtime_error("Failed to create KMAC context: " + std::to_string(ERR_get_error()));
  }

  OSSL_PARAM params[3];
  size_t paramCount = 0;

  params[paramCount++] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &outputLen);

  std::vector<uint8_t> custData;
  if (customization.has_value() && customization.value()->size() > 0) {
    const auto& custBuf = customization.value();
    custData.assign(reinterpret_cast<const uint8_t*>(custBuf->data()), reinterpret_cast<const uint8_t*>(custBuf->data()) + custBuf->size());
    params[paramCount++] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_CUSTOM, custData.data(), custData.size());
  }

  params[paramCount] = OSSL_PARAM_construct_end();

  const uint8_t* keyData = reinterpret_cast<const uint8_t*>(key->data());
  size_t keySize = key->size();

  if (keySize == 0) {
    throw std::runtime_error("KMAC key must not be empty");
  }

  if (EVP_MAC_init(ctx, keyData, keySize, params) != 1) {
    throw std::runtime_error("Failed to initialize KMAC: " + std::to_string(ERR_get_error()));
  }
}

void HybridKmac::update(const std::shared_ptr<ArrayBuffer>& data) {
  if (!ctx) {
    throw std::runtime_error("KMAC context not initialized");
  }

  if (EVP_MAC_update(ctx, reinterpret_cast<const uint8_t*>(data->data()), data->size()) != 1) {
    throw std::runtime_error("Failed to update KMAC: " + std::to_string(ERR_get_error()));
  }
}

std::shared_ptr<ArrayBuffer> HybridKmac::digest() {
  if (!ctx) {
    throw std::runtime_error("KMAC context not initialized");
  }

  uint8_t* buffer = new uint8_t[outputLen];

  if (EVP_MAC_final(ctx, buffer, nullptr, outputLen) != 1) {
    delete[] buffer;
    throw std::runtime_error("Failed to finalize KMAC digest: " + std::to_string(ERR_get_error()));
  }

  return std::make_shared<NativeArrayBuffer>(buffer, outputLen, [=]() { delete[] buffer; });
}

} // namespace margelo::nitro::crypto
