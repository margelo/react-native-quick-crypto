#pragma once

#include <memory>
#include <openssl/evp.h>
#include <string>
#include <vector>

#include "HybridDiffieHellmanSpec.hpp"

namespace margelo::nitro::crypto {

using namespace facebook;
using margelo::nitro::ArrayBuffer;

class HybridDiffieHellman : public HybridDiffieHellmanSpec {
 public:
  HybridDiffieHellman() : HybridObject("DiffieHellman") {}
  virtual ~HybridDiffieHellman() {
    if (_pkey) {
      EVP_PKEY_free(_pkey);
      _pkey = nullptr;
    }
  }

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

 private:
  EVP_PKEY* _pkey = nullptr;

  void ensureInitialized();
};

} // namespace margelo::nitro::crypto
