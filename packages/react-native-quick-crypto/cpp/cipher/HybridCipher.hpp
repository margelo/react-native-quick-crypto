#include <memory>
#include <NitroModules/ArrayBuffer.hpp>
#include <openssl/evp.h>
#include <optional>
#include <string>
#include <vector>

#include "HybridCipherSpec.hpp"
#include "CipherArgs.hpp"

namespace margelo::nitro::crypto {

using namespace facebook;

class HybridCipher : public HybridCipherSpec {
 public:
  HybridCipher() : HybridObject(TAG) {}
  ~HybridCipher();

 public:
  // Methods
  std::shared_ptr<ArrayBuffer>
  update(
    const std::shared_ptr<ArrayBuffer>& data
  ) override;

  std::shared_ptr<ArrayBuffer>
  final() override;

  void
  setArgs(
    const CipherArgs& args
  ) override;

  bool
  setAAD(
    const std::shared_ptr<ArrayBuffer>& data,
    std::optional<double> plaintextLength
  ) override;

  bool
  setAutoPadding(
    bool autoPad
  ) override;

  bool
  setAuthTag(
    const std::shared_ptr<ArrayBuffer>& tag
  ) override;

  std::shared_ptr<ArrayBuffer>
  getAuthTag() override;

  std::vector<std::string>
  getSupportedCiphers() override;

 private:
  // Methods
  void init();

  inline
  int getMode() {
    if (!ctx) {
      throw std::runtime_error("Cipher not initialized. Did you call setArgs()?");
    }
    return EVP_CIPHER_CTX_get_mode(ctx);
  }

 private:
  // Properties
  std::optional<CipherArgs> args = std::nullopt;
  EVP_CIPHER_CTX *ctx = nullptr;

};

} // namespace margelo::nitro::crypto
