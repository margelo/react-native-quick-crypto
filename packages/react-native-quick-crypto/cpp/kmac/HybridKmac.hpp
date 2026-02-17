#pragma once

#include <NitroModules/ArrayBuffer.hpp>
#include <memory>
#include <openssl/evp.h>
#include <string>

#include "HybridKmacSpec.hpp"

namespace margelo::nitro::crypto {

using namespace facebook;

using EVP_MAC_CTX_ptr = std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)>;

class HybridKmac : public HybridKmacSpec {
 public:
  HybridKmac() : HybridObject(TAG) {}

 public:
  void createKmac(const std::string& algorithm, const std::shared_ptr<ArrayBuffer>& key, double outputLength,
                  const std::optional<std::shared_ptr<ArrayBuffer>>& customization) override;
  void update(const std::shared_ptr<ArrayBuffer>& data) override;
  std::shared_ptr<ArrayBuffer> digest() override;

 private:
  EVP_MAC_CTX_ptr ctx{nullptr, EVP_MAC_CTX_free};
  size_t outputLen = 0;
};

} // namespace margelo::nitro::crypto
