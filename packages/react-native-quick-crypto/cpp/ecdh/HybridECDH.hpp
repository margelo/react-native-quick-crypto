#pragma once

#include <memory>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include <string>
#include <vector>

#include "HybridECDHSpec.hpp"

namespace margelo::nitro::crypto {

using namespace facebook;
using margelo::nitro::ArrayBuffer;

class HybridECDH : public HybridECDHSpec {
 public:
  HybridECDH() : HybridObject("ECDH") {}
  virtual ~HybridECDH() {
    if (_pkey) {
      EVP_PKEY_free(_pkey);
      _pkey = nullptr;
    }
    if (_group) {
      EC_GROUP_free(_group);
      _group = nullptr;
    }
  }

  void init(const std::string& curveName) override;
  std::shared_ptr<ArrayBuffer> generateKeys() override;
  std::shared_ptr<ArrayBuffer> computeSecret(const std::shared_ptr<ArrayBuffer>& otherPublicKey) override;
  std::shared_ptr<ArrayBuffer> getPrivateKey() override;
  void setPrivateKey(const std::shared_ptr<ArrayBuffer>& privateKey) override;
  std::shared_ptr<ArrayBuffer> getPublicKey() override;
  void setPublicKey(const std::shared_ptr<ArrayBuffer>& publicKey) override;

 private:
  EVP_PKEY* _pkey = nullptr;
  EC_GROUP* _group = nullptr;
  std::string _curveName;
  int _curveNid = 0;

  void ensureInitialized();
  int getCurveNid(const std::string& name);
};

} // namespace margelo::nitro::crypto
