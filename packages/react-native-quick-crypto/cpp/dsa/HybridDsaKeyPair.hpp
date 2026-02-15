#pragma once

#include <memory>
#include <openssl/evp.h>

#include "HybridDsaKeyPairSpec.hpp"
#include "QuickCryptoUtils.hpp"

namespace margelo::nitro::crypto {

class HybridDsaKeyPair : public HybridDsaKeyPairSpec {
 public:
  HybridDsaKeyPair() : HybridObject(TAG) {}
  ~HybridDsaKeyPair() override = default;

 public:
  std::shared_ptr<Promise<void>> generateKeyPair() override;
  void generateKeyPairSync() override;
  void setModulusLength(double modulusLength) override;
  void setDivisorLength(double divisorLength) override;
  std::shared_ptr<ArrayBuffer> getPublicKey() override;
  std::shared_ptr<ArrayBuffer> getPrivateKey() override;

 private:
  int modulusLength_ = 0;
  int divisorLength_ = -1;

  using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
  EVP_PKEY_ptr pkey_{nullptr, EVP_PKEY_free};
};

} // namespace margelo::nitro::crypto
