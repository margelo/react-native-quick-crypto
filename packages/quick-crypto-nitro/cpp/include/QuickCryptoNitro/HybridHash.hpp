#pragma once

#include "HashBackend.hpp"
#include <QuickCryptoNitro/HybridHashSpec.hpp>

namespace margelo::nitro::quickcrypto {

class HybridHash final : public HybridHashSpec {
 public:
  explicit HybridHash(const std::string& algorithm);
  void update(const ArrayBuffer& data) override;
  ArrayBuffer digest() override;

 private:
  ::margelo::quickcrypto::HashBackend backend;
};

} // namespace margelo::nitro::quickcrypto
