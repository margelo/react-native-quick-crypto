#pragma once

#include <memory>
#include <openssl/evp.h>

#include "HybridDsaKeyPairSpec.hpp"
#include "QuickCryptoUtils.hpp"

namespace margelo::nitro::crypto {

class HybridDsaKeyPair : public HybridDsaKeyPairSpec {
 public:
  HybridDsaKeyPair() : HybridObject(TAG) {}
  ~HybridDsaKeyPair() override {
    if (pkey != nullptr) {
      EVP_PKEY_free(pkey);
      pkey = nullptr;
    }
  }

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
  EVP_PKEY* pkey = nullptr;
};

} // namespace margelo::nitro::crypto
