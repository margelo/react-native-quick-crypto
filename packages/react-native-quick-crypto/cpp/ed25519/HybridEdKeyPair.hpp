#include <openssl/evp.h>
#include <openssl/err.h>
#include <memory>
#include <string>

#include "HybridEdKeyPairSpec.hpp"
#include "Utils.hpp"

namespace margelo::nitro::crypto {

using namespace facebook;

class HybridEdKeyPair : public HybridEdKeyPairSpec {
 public:
  HybridEdKeyPair() : HybridObject(TAG) {}

 public:
  // Methods
  std::shared_ptr<Promise<void>>
  generateKeyPair(
    double publicFormat,
    double publicType,
    double privateFormat,
    double privateType,
    const std::optional<std::string>& cipher,
    const std::optional<std::shared_ptr<ArrayBuffer>>& passphrase
  ) override;

  void
  generateKeyPairSync(
    double publicFormat,
    double publicType,
    double privateFormat,
    double privateType,
    const std::optional<std::string>& cipher,
    const std::optional<std::shared_ptr<ArrayBuffer>>& passphrase
  ) override;

  std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>>
  sign(const std::shared_ptr<ArrayBuffer>& message) override;

  std::shared_ptr<ArrayBuffer>
  signSync(const std::shared_ptr<ArrayBuffer>& message) override;

  std::shared_ptr<Promise<bool>>
  verify(
    const std::shared_ptr<ArrayBuffer>& signature,
    const std::shared_ptr<ArrayBuffer>& message
  ) override;

  bool
  verifySync(
    const std::shared_ptr<ArrayBuffer>& signature,
    const std::shared_ptr<ArrayBuffer>& message
  ) override;

 protected:
  std::shared_ptr<ArrayBuffer>
  getPublicKey() override;

  virtual std::shared_ptr<ArrayBuffer>
  getPrivateKey();

  virtual void
  checkKeyPair();

  void
  setCurve(const std::string& curve) override;

 private:
  std::string curve;
  EVP_PKEY* pkey = nullptr;
};

} // namespace margelo::nitro::crypto
