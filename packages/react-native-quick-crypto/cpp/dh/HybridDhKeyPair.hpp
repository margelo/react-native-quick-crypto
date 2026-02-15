#pragma once

#include <memory>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <string>
#include <vector>

#include "HybridDhKeyPairSpec.hpp"
#include "QuickCryptoUtils.hpp"

namespace margelo::nitro::crypto {

class HybridDhKeyPair : public HybridDhKeyPairSpec {
 public:
  HybridDhKeyPair() : HybridObject(TAG) {}
  ~HybridDhKeyPair() override = default;

 public:
  std::shared_ptr<Promise<void>> generateKeyPair() override;
  void generateKeyPairSync() override;
  void setPrimeLength(double primeLength) override;
  void setPrime(const std::shared_ptr<ArrayBuffer>& prime) override;
  void setGenerator(double generator) override;
  void setGroupName(const std::string& groupName) override;
  std::shared_ptr<ArrayBuffer> getPublicKey() override;
  std::shared_ptr<ArrayBuffer> getPrivateKey() override;

 private:
  int primeLength_ = 0;
  std::vector<uint8_t> prime_;
  int generator_ = 2;
  std::string groupName_;

  using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
  EVP_PKEY_ptr pkey_{nullptr, EVP_PKEY_free};
};

} // namespace margelo::nitro::crypto
