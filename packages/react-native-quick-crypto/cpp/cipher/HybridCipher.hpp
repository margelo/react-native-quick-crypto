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
  void init(
    const std::shared_ptr<ArrayBuffer> cipher_key,
    const std::shared_ptr<ArrayBuffer> iv
  );

  bool isAuthenticatedMode() const;

  bool initAuthenticated(
    const char *cipher_type,
    int iv_len,
    unsigned int auth_tag_len,
    const std::shared_ptr<NativeArrayBuffer>& native_iv
  );

  bool maybePassAuthTagToOpenSSL();

  bool checkCCMMessageLength(int message_len);

  bool initCCMMode(
    int iv_len,
    const std::shared_ptr<NativeArrayBuffer>& native_iv
  );
  bool initGCMMode();
  bool initOCBMode(const std::shared_ptr<NativeArrayBuffer>& native_iv);
  bool initSIVMode();
  bool initGCMSIVMode();
  bool initChaCha20Poly1305();

  // Helper function to set authentication tag length
  bool setAuthTagLength(const char* mode_str);

  int getMode();

 private:
  // Properties
  bool is_cipher = true;
  std::string cipher_type;
  EVP_CIPHER_CTX *ctx = nullptr;
  bool pending_auth_failed = false;
  bool has_aad = false;
  uint8_t auth_tag[EVP_GCM_TLS_TAG_LEN];
  AuthTagState auth_tag_state;
  unsigned int auth_tag_len;
  int max_message_size;
};

} // namespace margelo::nitro::crypto
