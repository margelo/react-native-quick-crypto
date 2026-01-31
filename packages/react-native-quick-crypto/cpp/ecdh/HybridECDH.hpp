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

using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using EC_GROUP_ptr = std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)>;

class HybridECDH : public HybridECDHSpec {
 public:
  HybridECDH() : HybridObject("ECDH"), _pkey(nullptr, EVP_PKEY_free), _group(nullptr, EC_GROUP_free) {}
  virtual ~HybridECDH() = default;

  void init(const std::string& curveName) override;
  std::shared_ptr<ArrayBuffer> generateKeys() override;
  std::shared_ptr<ArrayBuffer> computeSecret(const std::shared_ptr<ArrayBuffer>& otherPublicKey) override;
  std::shared_ptr<ArrayBuffer> getPrivateKey() override;
  void setPrivateKey(const std::shared_ptr<ArrayBuffer>& privateKey) override;
  std::shared_ptr<ArrayBuffer> getPublicKey() override;
  void setPublicKey(const std::shared_ptr<ArrayBuffer>& publicKey) override;

 private:
  EVP_PKEY_ptr _pkey;
  EC_GROUP_ptr _group;
  std::string _curveName;
  int _curveNid = 0;

  void ensureInitialized() const;
  static int getCurveNid(const std::string& name);
};

} // namespace margelo::nitro::crypto
