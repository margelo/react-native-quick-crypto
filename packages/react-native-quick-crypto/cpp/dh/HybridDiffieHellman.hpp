#pragma once

#include <memory>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <string>
#include <vector>

#include "HybridDiffieHellmanSpec.hpp"

namespace margelo::nitro::crypto {

using namespace facebook;
using margelo::nitro::ArrayBuffer;

using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

class HybridDiffieHellman : public HybridDiffieHellmanSpec {
 public:
  HybridDiffieHellman() : HybridObject("DiffieHellman"), _pkey(nullptr, EVP_PKEY_free) {}
  virtual ~HybridDiffieHellman() = default;

  void init(const std::shared_ptr<ArrayBuffer>& prime, const std::shared_ptr<ArrayBuffer>& generator) override;
  void initWithSize(double primeLength, double generator) override;
  std::shared_ptr<ArrayBuffer> generateKeys() override;
  std::shared_ptr<ArrayBuffer> computeSecret(const std::shared_ptr<ArrayBuffer>& otherPublicKey) override;
  std::shared_ptr<ArrayBuffer> getPrime() override;
  std::shared_ptr<ArrayBuffer> getGenerator() override;
  std::shared_ptr<ArrayBuffer> getPublicKey() override;
  std::shared_ptr<ArrayBuffer> getPrivateKey() override;
  void setPublicKey(const std::shared_ptr<ArrayBuffer>& publicKey) override;
  void setPrivateKey(const std::shared_ptr<ArrayBuffer>& privateKey) override;
  double getVerifyError() override;

 private:
  EVP_PKEY_ptr _pkey;

  void ensureInitialized() const;
  const DH* getDH() const;
};

} // namespace margelo::nitro::crypto
