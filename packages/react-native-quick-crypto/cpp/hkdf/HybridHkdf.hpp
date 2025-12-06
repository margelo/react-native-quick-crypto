#pragma once

#include <NitroModules/ArrayBuffer.hpp>
#include <memory>
#include <openssl/evp.h>
#include <string>

#include "HybridHkdfSpec.hpp"

namespace margelo::nitro::crypto {

using namespace facebook;

class HybridHkdf : public HybridHkdfSpec {
 public:
  HybridHkdf() : HybridObject(TAG) {}

 public:
  // Methods
  std::shared_ptr<ArrayBuffer> deriveKey(const std::string& algorithm, const std::shared_ptr<ArrayBuffer>& key,
                                         const std::shared_ptr<ArrayBuffer>& salt, const std::shared_ptr<ArrayBuffer>& info,
                                         double length) override;
};

} // namespace margelo::nitro::crypto
