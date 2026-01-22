#include <memory>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <string>

#include "HybridEcKeyPairSpec.hpp"
#include "QuickCryptoUtils.hpp"

namespace margelo::nitro::crypto {

class HybridEcKeyPair : public HybridEcKeyPairSpec {
 public:
  HybridEcKeyPair() : HybridObject(TAG) {}
  ~HybridEcKeyPair() {
    if (pkey != nullptr) {
      EVP_PKEY_free(pkey);
      pkey = nullptr;
    }
  }

 public:
  // Methods
  std::shared_ptr<Promise<void>> generateKeyPair() override;
  void generateKeyPairSync() override;
  KeyObject importKey(const std::string& format, const std::shared_ptr<ArrayBuffer>& keyData, const std::string& algorithm,
                      bool extractable, const std::vector<std::string>& keyUsages) override;
  std::shared_ptr<ArrayBuffer> exportKey(const KeyObject& key, const std::string& format) override;
  std::shared_ptr<ArrayBuffer> getPublicKey() override;
  std::shared_ptr<ArrayBuffer> getPrivateKey() override;

  void setCurve(const std::string& curve) override;
  std::shared_ptr<ArrayBuffer> sign(const std::shared_ptr<ArrayBuffer>& data, const std::string& hashAlgorithm) override;
  bool verify(const std::shared_ptr<ArrayBuffer>& data, const std::shared_ptr<ArrayBuffer>& signature,
              const std::string& hashAlgorithm) override;

 protected:
  void checkKeyPair();

 private:
  std::string curve;
  EVP_PKEY* pkey = nullptr;

  static int GetCurveFromName(const char* name);
};

} // namespace margelo::nitro::crypto
