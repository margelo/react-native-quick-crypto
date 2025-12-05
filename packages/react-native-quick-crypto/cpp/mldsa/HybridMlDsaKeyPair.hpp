#pragma once

#include <memory>
#include <openssl/evp.h>
#include <string>

#include "HybridMlDsaKeyPairSpec.hpp"

namespace margelo::nitro::crypto {

class HybridMlDsaKeyPair : public HybridMlDsaKeyPairSpec {
 public:
  HybridMlDsaKeyPair() : HybridObject(TAG) {}
  ~HybridMlDsaKeyPair();

  std::shared_ptr<Promise<void>> generateKeyPair(double publicFormat, double publicType, double privateFormat, double privateType) override;

  void generateKeyPairSync(double publicFormat, double publicType, double privateFormat, double privateType) override;

  std::shared_ptr<ArrayBuffer> getPublicKey() override;
  std::shared_ptr<ArrayBuffer> getPrivateKey() override;

  std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>> sign(const std::shared_ptr<ArrayBuffer>& message) override;

  std::shared_ptr<ArrayBuffer> signSync(const std::shared_ptr<ArrayBuffer>& message) override;

  std::shared_ptr<Promise<bool>> verify(const std::shared_ptr<ArrayBuffer>& signature,
                                        const std::shared_ptr<ArrayBuffer>& message) override;

  bool verifySync(const std::shared_ptr<ArrayBuffer>& signature, const std::shared_ptr<ArrayBuffer>& message) override;

  void setVariant(const std::string& variant) override;

 private:
  std::string variant_;
  EVP_PKEY* pkey_ = nullptr;

  int publicFormat_ = -1;
  int publicType_ = -1;
  int privateFormat_ = -1;
  int privateType_ = -1;

  void checkKeyPair();
  int getEvpPkeyType() const;
};

} // namespace margelo::nitro::crypto
