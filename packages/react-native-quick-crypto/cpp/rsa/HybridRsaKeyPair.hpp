#pragma once

#include "HybridRsaKeyPairSpec.hpp"
#include <NitroModules/ArrayBuffer.hpp>
#include <NitroModules/Promise.hpp>
#include <memory>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <string>
#include <vector>

namespace margelo::nitro::crypto {

class HybridRsaKeyPair : public HybridRsaKeyPairSpec {
 public:
  HybridRsaKeyPair() : HybridObject(TAG), modulusLength(2048), hashAlgorithm("SHA-256") {}
  ~HybridRsaKeyPair() override = default;

  std::shared_ptr<Promise<void>> generateKeyPair() override;
  void generateKeyPairSync() override;
  void setModulusLength(double modulusLength) override;
  void setPublicExponent(const std::shared_ptr<ArrayBuffer>& publicExponent) override;
  void setHashAlgorithm(const std::string& hashAlgorithm) override;
  std::shared_ptr<ArrayBuffer> getPublicKey() override;
  std::shared_ptr<ArrayBuffer> getPrivateKey() override;
  KeyObject importKey(const std::string& format, const std::shared_ptr<ArrayBuffer>& keyData, const std::string& algorithm,
                      bool extractable, const std::vector<std::string>& keyUsages) override;
  std::shared_ptr<ArrayBuffer> exportKey(const KeyObject& key, const std::string& format) override;

 private:
  using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
  EVP_PKEY_ptr pkey_{nullptr, EVP_PKEY_free};
  int modulusLength;
  std::vector<unsigned char> publicExponent;
  std::string hashAlgorithm;

  void checkKeyPair();
};

} // namespace margelo::nitro::crypto
