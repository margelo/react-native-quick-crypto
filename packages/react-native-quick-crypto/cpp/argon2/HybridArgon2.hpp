#pragma once

#include <NitroModules/ArrayBuffer.hpp>
#include <NitroModules/Promise.hpp>
#include <memory>
#include <optional>
#include <string>

#include "HybridArgon2Spec.hpp"

namespace margelo::nitro::crypto {

using namespace facebook;

class HybridArgon2 : public HybridArgon2Spec {
 public:
  HybridArgon2() : HybridObject(TAG) {}

 public:
  std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>> hash(const std::string& algorithm, const std::shared_ptr<ArrayBuffer>& message,
                                                              const std::shared_ptr<ArrayBuffer>& nonce, double parallelism,
                                                              double tagLength, double memory, double passes, double version,
                                                              const std::optional<std::shared_ptr<ArrayBuffer>>& secret,
                                                              const std::optional<std::shared_ptr<ArrayBuffer>>& associatedData) override;

  std::shared_ptr<ArrayBuffer> hashSync(const std::string& algorithm, const std::shared_ptr<ArrayBuffer>& message,
                                        const std::shared_ptr<ArrayBuffer>& nonce, double parallelism, double tagLength, double memory,
                                        double passes, double version, const std::optional<std::shared_ptr<ArrayBuffer>>& secret,
                                        const std::optional<std::shared_ptr<ArrayBuffer>>& associatedData) override;
};

} // namespace margelo::nitro::crypto
