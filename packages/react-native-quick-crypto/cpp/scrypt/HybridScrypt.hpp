#pragma once

#include <NitroModules/ArrayBuffer.hpp>
#include <NitroModules/Promise.hpp>
#include <memory>
#include <openssl/evp.h>
#include <string>

#include "HybridScryptSpec.hpp"

namespace margelo::nitro::crypto {

using namespace facebook;

class HybridScrypt : public HybridScryptSpec {
 public:
  HybridScrypt() : HybridObject(TAG) {}

 public:
  // Methods
  std::shared_ptr<ArrayBuffer> deriveKeySync(const std::shared_ptr<ArrayBuffer>& password, const std::shared_ptr<ArrayBuffer>& salt,
                                             double N, double r, double p, double maxmem, double keylen) override;
  std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>> deriveKey(const std::shared_ptr<ArrayBuffer>& password,
                                                                   const std::shared_ptr<ArrayBuffer>& salt, double N, double r, double p,
                                                                   double maxmem, double keylen) override;
};

} // namespace margelo::nitro::crypto
