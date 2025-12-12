#pragma once

#include "HybridUtilsSpec.hpp"

namespace margelo::nitro::crypto {

class HybridUtils : public HybridUtilsSpec {
 public:
  HybridUtils() : HybridObject(TAG) {}

 public:
  bool timingSafeEqual(const std::shared_ptr<ArrayBuffer>& a, const std::shared_ptr<ArrayBuffer>& b) override;
};

} // namespace margelo::nitro::crypto
