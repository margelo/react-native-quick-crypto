#pragma once

#include <memory>
#include <openssl/evp.h>
#include <string>

#include "HybridMlKemKeyPairSpec.hpp"

namespace margelo::nitro::crypto {

class HybridMlKemKeyPair : public HybridMlKemKeyPairSpec {
 public:
  HybridMlKemKeyPair() : HybridObject(TAG) {}
  ~HybridMlKemKeyPair();

  void setVariant(const std::string& variant) override;

  std::shared_ptr<Promise<void>> generateKeyPair(double publicFormat, double publicType, double privateFormat, double privateType) override;
  void generateKeyPairSync(double publicFormat, double publicType, double privateFormat, double privateType) override;

  std::shared_ptr<ArrayBuffer> getPublicKey() override;
  std::shared_ptr<ArrayBuffer> getPrivateKey() override;

  void setPublicKey(const std::shared_ptr<ArrayBuffer>& keyData, double format, double type) override;
  void setPrivateKey(const std::shared_ptr<ArrayBuffer>& keyData, double format, double type) override;

  std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>> encapsulate() override;
  std::shared_ptr<ArrayBuffer> encapsulateSync() override;

  std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>> decapsulate(const std::shared_ptr<ArrayBuffer>& ciphertext) override;
  std::shared_ptr<ArrayBuffer> decapsulateSync(const std::shared_ptr<ArrayBuffer>& ciphertext) override;

 private:
  std::string variant_;
  EVP_PKEY* pkey_ = nullptr;

  int publicFormat_ = -1;
  int publicType_ = -1;
  int privateFormat_ = -1;
  int privateType_ = -1;

  void checkKeyPair();
};

} // namespace margelo::nitro::crypto
