#pragma once

#include <NitroModules/ArrayBuffer.hpp>
#include <memory>
#include <openssl/evp.h>
#include <string>

#include "HybridKmacSpec.hpp"

namespace margelo::nitro::crypto {

using namespace facebook;

class HybridKmac : public HybridKmacSpec {
 public:
  HybridKmac() : HybridObject(TAG) {}
  ~HybridKmac();

 public:
  void createKmac(const std::string& algorithm, const std::shared_ptr<ArrayBuffer>& key, double outputLength,
                  const std::optional<std::shared_ptr<ArrayBuffer>>& customization) override;
  void update(const std::shared_ptr<ArrayBuffer>& data) override;
  std::shared_ptr<ArrayBuffer> digest() override;

 private:
  EVP_MAC_CTX* ctx = nullptr;
  size_t outputLen = 0;
};

} // namespace margelo::nitro::crypto
