#pragma once

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <optional>
#include <string>
#include <vector>

#include "HybridCipherSpec.hpp"

namespace margelo::nitro::crypto {

// Default tag length for OCB, SIV, CCM, ChaCha20-Poly1305
constexpr unsigned kDefaultAuthTagLength = 16;

class HybridCipher : public HybridCipherSpec {
 public:
  HybridCipher() : HybridObject(TAG) {}
  ~HybridCipher() override;

 public:
  // Methods
  std::shared_ptr<ArrayBuffer> update(const std::shared_ptr<ArrayBuffer>& data) override;

  std::shared_ptr<ArrayBuffer> final() override;

  virtual void init(const std::shared_ptr<ArrayBuffer> cipher_key, const std::shared_ptr<ArrayBuffer> iv);

  void setArgs(const CipherArgs& args) override;

  bool setAAD(const std::shared_ptr<ArrayBuffer>& data, std::optional<double> plaintextLength) override;

  bool setAutoPadding(bool autoPad) override;

  bool setAuthTag(const std::shared_ptr<ArrayBuffer>& tag) override;

  std::shared_ptr<ArrayBuffer> getAuthTag() override;

  std::vector<std::string> getSupportedCiphers() override;

 protected:
  // Protected enums for state management
  enum CipherKind { kCipher, kDecipher };
  enum UpdateResult { kSuccess, kErrorMessageSize, kErrorState };
  enum AuthTagState { kAuthTagUnknown, kAuthTagKnown, kAuthTagPassedToOpenSSL };

  // Virtual methods for cipher-specific implementations
  virtual const EVP_CIPHER* getCipherImpl() = 0;
  virtual void validateKeySize(size_t key_size) const = 0;
  virtual void validateIVSize(size_t iv_size) const = 0;
  virtual std::string getCipherName() const = 0;

 protected:
  // Properties
  bool is_cipher = true;
  std::string cipher_type;
  EVP_CIPHER_CTX* ctx = nullptr;
  bool pending_auth_failed = false;
  bool has_aad = false;
  uint8_t auth_tag[EVP_GCM_TLS_TAG_LEN];
  AuthTagState auth_tag_state;
  unsigned int auth_tag_len = 0;
  int max_message_size;

 protected:
  // Methods
  int getMode();
  void checkCtx() const;
  bool maybePassAuthTagToOpenSSL();
};

} // namespace margelo::nitro::crypto
