#pragma once

#include "HybridUtilsSpec.hpp"

namespace margelo::nitro::crypto {

class HybridUtils : public HybridUtilsSpec {
 public:
  HybridUtils() : HybridObject(TAG) {}

 public:
  bool timingSafeEqual(const std::shared_ptr<ArrayBuffer>& a, const std::shared_ptr<ArrayBuffer>& b) override;

 protected:
  void loadHybridMethods() override;

 private:
  facebook::jsi::Value bufferToJsiString(facebook::jsi::Runtime& runtime, const facebook::jsi::Value& thisArg,
                                         const facebook::jsi::Value* args, size_t argCount);
  facebook::jsi::Value jsiStringToBuffer(facebook::jsi::Runtime& runtime, const facebook::jsi::Value& thisArg,
                                         const facebook::jsi::Value* args, size_t argCount);
};

} // namespace margelo::nitro::crypto
