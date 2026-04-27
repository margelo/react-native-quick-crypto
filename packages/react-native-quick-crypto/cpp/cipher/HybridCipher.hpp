#pragma once

#include <memory>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <optional>
#include <string>
#include <vector>

#include "CipherInfo.hpp"
#include "HybridCipherSpec.hpp"

namespace margelo::nitro::crypto {

// Owning smart pointer for EVP_CIPHER_CTX. Living in the base class means
// subclasses never have to remember to free it — the destruction order
// (subclass → base) automatically calls the deleter when the cipher object
// goes away. The previous design required each subclass to handle ctx in
// its destructor, and three subclasses (CCM, ChaCha20, ChaCha20-Poly1305)
// got it wrong by setting `ctx = nullptr` without calling the free first,
// leaking the OpenSSL cipher context. See audit Phase 1.3.
using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

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

  std::optional<CipherInfo> getCipherInfo(const std::string& name, std::optional<double> keyLength,
                                          std::optional<double> ivLength) override;

 protected:
  // Protected enums for state management
  enum CipherKind { kCipher, kDecipher };
  enum UpdateResult { kSuccess, kErrorMessageSize, kErrorState };
  enum AuthTagState { kAuthTagUnknown, kAuthTagKnown, kAuthTagPassedToOpenSSL };

 protected:
  // Properties
  bool is_cipher = true;
  bool is_finalized = false;
  std::string cipher_type;
  EvpCipherCtxPtr ctx{nullptr, EVP_CIPHER_CTX_free};
  bool pending_auth_failed = false;
  bool has_aad = false;
  // Tracks whether update() has been called on this cipher. Used to enforce
  // the AEAD ordering invariant that setAAD() must precede any update() call;
  // OpenSSL silently accepts misordered AAD/data on some modes (OCB,
  // ChaCha20-Poly1305), letting an attacker truncate authenticated data.
  bool has_update_called = false;
  uint8_t auth_tag[EVP_GCM_TLS_TAG_LEN];
  AuthTagState auth_tag_state;
  unsigned int auth_tag_len = 0;
  int max_message_size;

 protected:
  // Methods
  int getMode();
  void checkCtx() const;
  void checkNotFinalized() const;
  void checkAADBeforeUpdate() const;
  bool maybePassAuthTagToOpenSSL();
};

} // namespace margelo::nitro::crypto
