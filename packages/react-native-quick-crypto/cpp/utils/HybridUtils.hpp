#pragma once

#include "HybridUtilsSpec.hpp"

namespace margelo::nitro::crypto {

class HybridUtils : public HybridUtilsSpec {
 public:
  HybridUtils() : HybridObject(TAG) {}

 public:
  bool timingSafeEqual(const std::shared_ptr<ArrayBuffer>& a, const std::shared_ptr<ArrayBuffer>& b) override;
  std::string bufferToString(const std::shared_ptr<ArrayBuffer>& buffer, const std::string& encoding) override;
  std::shared_ptr<ArrayBuffer> stringToBuffer(const std::string& str, const std::string& encoding) override;
};

} // namespace margelo::nitro::crypto
