#pragma once

#include "HybridCertificateSpec.hpp"

namespace margelo::nitro::crypto {

class HybridCertificate : public HybridCertificateSpec {
 public:
  HybridCertificate() : HybridObject(TAG) {}

  bool verifySpkac(const std::shared_ptr<ArrayBuffer>& spkac) override;
  std::shared_ptr<ArrayBuffer> exportPublicKey(const std::shared_ptr<ArrayBuffer>& spkac) override;
  std::shared_ptr<ArrayBuffer> exportChallenge(const std::shared_ptr<ArrayBuffer>& spkac) override;
};

} // namespace margelo::nitro::crypto
