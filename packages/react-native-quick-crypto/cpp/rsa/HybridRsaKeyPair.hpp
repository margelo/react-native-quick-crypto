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
  HybridRsaKeyPair() : HybridObject(TAG), pkey(nullptr), modulusLength(2048), hashAlgorithm("SHA-256") {}
  ~HybridRsaKeyPair() {
    if (pkey) {
      EVP_PKEY_free(pkey);
    }
  }

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
  EVP_PKEY* pkey;
  int modulusLength;
  std::vector<unsigned char> publicExponent;
  std::string hashAlgorithm;

  void checkKeyPair();
};

} // namespace margelo::nitro::crypto
