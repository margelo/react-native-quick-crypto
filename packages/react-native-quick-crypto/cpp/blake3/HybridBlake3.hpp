#pragma once

#include <memory>
#include <optional>
#include <string>

#include "HybridBlake3Spec.hpp"
#include "blake3.h"

namespace margelo::nitro::crypto {

class HybridBlake3 : public HybridBlake3Spec {
 public:
  HybridBlake3() : HybridObject(TAG) {}
  ~HybridBlake3() = default;

 public:
  void initHash() override;
  void initKeyed(const std::shared_ptr<ArrayBuffer>& key) override;
  void initDeriveKey(const std::string& context) override;
  void update(const std::shared_ptr<ArrayBuffer>& data) override;
  std::shared_ptr<ArrayBuffer> digest(std::optional<double> length) override;
  void reset() override;
  std::shared_ptr<HybridBlake3Spec> copy() override;
  std::string getVersion() override;

 private:
  blake3_hasher hasher;
  bool initialized = false;
  enum class Mode { Hash, Keyed, DeriveKey } mode = Mode::Hash;
  std::optional<std::array<uint8_t, BLAKE3_KEY_LEN>> key;
  std::optional<std::string> context;
};

} // namespace margelo::nitro::crypto
