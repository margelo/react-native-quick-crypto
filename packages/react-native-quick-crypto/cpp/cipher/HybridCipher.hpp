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
 protected:
  enum CipherKind { kCipher, kDecipher };
  enum UpdateResult { kSuccess, kErrorMessageSize, kErrorState };
  enum AuthTagState { kAuthTagUnknown, kAuthTagKnown, kAuthTagPassedToOpenSSL };

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

  bool isAuthenticatedMode() const;

  bool initAuthenticated(
    const char *cipher_type,
    int iv_len,
    unsigned int auth_tag_len
  );

  bool maybePassAuthTagToOpenSSL();

  bool checkCCMMessageLength(int message_len);

  inline const CipherArgs& getArgs() {
    // check if args are set
    if (!args.has_value()) {
      throw std::runtime_error("CipherArgs not set");
    }
    return args.value();
  }

  inline int getMode() {
    if (!ctx) {
      throw std::runtime_error("Cipher not initialized. Did you call setArgs()?");
    }
    return EVP_CIPHER_CTX_get_mode(ctx);
  }

 private:
  // Properties
  std::optional<CipherArgs> args = std::nullopt;
  EVP_CIPHER_CTX *ctx = nullptr;
  bool pending_auth_failed;
  char auth_tag[EVP_GCM_TLS_TAG_LEN];
  AuthTagState auth_tag_state;
  unsigned int auth_tag_len;
  int max_message_size;
};

} // namespace margelo::nitro::crypto
