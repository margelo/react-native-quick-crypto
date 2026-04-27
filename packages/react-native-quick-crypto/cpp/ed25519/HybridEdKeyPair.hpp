#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string>

#include "HybridEdKeyPairSpec.hpp"
#include "QuickCryptoUtils.hpp"

namespace margelo::nitro::crypto {

class HybridEdKeyPair : public HybridEdKeyPairSpec {
 public:
  HybridEdKeyPair() : HybridObject(TAG) {}
  ~HybridEdKeyPair() override = default;

 public:
  // Methods
  std::shared_ptr<ArrayBuffer> diffieHellman(const std::shared_ptr<ArrayBuffer>& privateKey,
                                             const std::shared_ptr<ArrayBuffer>& publicKey) override;

  std::shared_ptr<Promise<void>> generateKeyPair(double publicFormat, double publicType, double privateFormat, double privateType,
                                                 const std::optional<std::string>& cipher,
                                                 const std::optional<std::shared_ptr<ArrayBuffer>>& passphrase) override;

  void generateKeyPairSync(double publicFormat, double publicType, double privateFormat, double privateType,
                           const std::optional<std::string>& cipher,
                           const std::optional<std::shared_ptr<ArrayBuffer>>& passphrase) override;

  std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>> sign(const std::shared_ptr<ArrayBuffer>& message,
                                                              const std::optional<std::shared_ptr<ArrayBuffer>>& key) override;

  std::shared_ptr<ArrayBuffer> signSync(const std::shared_ptr<ArrayBuffer>& message,
                                        const std::optional<std::shared_ptr<ArrayBuffer>>& key) override;

  std::shared_ptr<Promise<bool>> verify(const std::shared_ptr<ArrayBuffer>& signature, const std::shared_ptr<ArrayBuffer>& message,
                                        const std::optional<std::shared_ptr<ArrayBuffer>>& key) override;

  bool verifySync(const std::shared_ptr<ArrayBuffer>& signature, const std::shared_ptr<ArrayBuffer>& message,
                  const std::optional<std::shared_ptr<ArrayBuffer>>& key) override;

 protected:
  std::shared_ptr<ArrayBuffer> getPublicKey() override;

  std::shared_ptr<ArrayBuffer> getPrivateKey() override;

  void checkKeyPair();

  void setCurve(const std::string& curve) override;

 private:
  std::string curve;
  using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
  EVP_PKEY_ptr pkey_{nullptr, EVP_PKEY_free};

  // Encoding configuration for key export
  // Format: -1 = default (raw), 0 = DER, 1 = PEM
  // Type: 0 = PKCS1, 1 = PKCS8, 2 = SPKI, 3 = SEC1
  int publicFormat_ = -1;
  int publicType_ = -1;
  int privateFormat_ = -1;
  int privateType_ = -1;

  EVP_PKEY_ptr importPublicKey(const std::optional<std::shared_ptr<ArrayBuffer>>& key);
  EVP_PKEY_ptr importPrivateKey(const std::optional<std::shared_ptr<ArrayBuffer>>& key);
};

} // namespace margelo::nitro::crypto
