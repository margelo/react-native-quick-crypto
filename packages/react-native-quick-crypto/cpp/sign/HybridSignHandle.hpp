#pragma once

#include <NitroModules/ArrayBuffer.hpp>
#include <memory>
#include <openssl/evp.h>
#include <optional>
#include <string>
#include <vector>

#include "HybridKeyObjectHandleSpec.hpp"
#include "HybridSignHandleSpec.hpp"

namespace margelo::nitro::crypto {

using namespace facebook;

class HybridSignHandle : public HybridSignHandleSpec {
 public:
  HybridSignHandle() : HybridObject(TAG) {}
  ~HybridSignHandle();

 public:
  void init(const std::string& algorithm) override;
  void update(const std::shared_ptr<ArrayBuffer>& data) override;
  std::shared_ptr<ArrayBuffer> sign(const std::shared_ptr<HybridKeyObjectHandleSpec>& keyHandle, std::optional<double> padding,
                                    std::optional<double> saltLength, std::optional<double> dsaEncoding) override;

 private:
  EVP_MD_CTX* md_ctx = nullptr;
  const EVP_MD* md = nullptr;
  std::string algorithm_name;
  // Buffer for accumulating data for one-shot signing (Ed25519/Ed448)
  std::vector<uint8_t> data_buffer;
};

} // namespace margelo::nitro::crypto
