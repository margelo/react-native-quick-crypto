#pragma once

#include <NitroModules/ArrayBuffer.hpp>
#include <NitroModules/Promise.hpp>
#include <memory>
#include <optional>
#include <string>

#include "HybridTurboShakeSpec.hpp"

namespace margelo::nitro::crypto {

using namespace facebook;

class HybridTurboShake : public HybridTurboShakeSpec {
 public:
  HybridTurboShake() : HybridObject(TAG) {}

 public:
  std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>> turboShake(TurboShakeVariant variant, double domainSeparation, double outputLength,
                                                                    const std::shared_ptr<ArrayBuffer>& data) override;

  std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>>
  kangarooTwelve(KangarooTwelveVariant variant, double outputLength, const std::shared_ptr<ArrayBuffer>& data,
                 const std::optional<std::shared_ptr<ArrayBuffer>>& customization) override;
};

} // namespace margelo::nitro::crypto
