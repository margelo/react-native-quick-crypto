#pragma once

#include "ncrypto.h"

#ifdef OPENSSL_IS_BORINGSSL

namespace ncrypto {

class AeadCtxPointer;

class Aead final {
 private:
  // BoringSSL does not keep a list of AEADs, so we need to maintain our own.
  struct AeadInfo {
    std::string name;
    int mode;
    int nid = 0; // Note: BoringSSL only defines NIDs for some AEADs
  };

 public:
  Aead() = default;
  Aead(const AeadInfo* info, const EVP_AEAD* aead) : aead_(aead), info_(info) {}
  Aead(const Aead&) = default;
  Aead& operator=(const Aead&) = default;
  NCRYPTO_DISALLOW_MOVE(Aead)

  inline const EVP_AEAD* get() const {
    return aead_;
  }
  std::string_view getModeLabel() const;
  inline operator const EVP_AEAD*() const {
    return aead_;
  }
  inline operator bool() const {
    return aead_ != nullptr;
  }

  int getMode() const;
  int getNonceLength() const;
  int getKeyLength() const;
  int getBlockSize() const;
  int getMaxOverhead() const;
  int getMaxTagLength() const;
  std::string_view getName() const;

  static const Aead FromName(std::string_view name);

  // TODO(npaun): BoringSSL does not define NIDs for all AEADs.
  // This method is included only for implementing getCipherInfo and can't be
  // used to construct an Aead instance.
  int getNid() const;
  // static const AEAD FromNid(int nid);

  static const Aead FromCtx(std::string_view name, const AeadCtxPointer& ctx);

  using AeadNameCallback = std::function<void(std::string_view name)>;

  // Iterates the known ciphers if the underlying implementation
  // is able to do so.
  static void ForEach(AeadNameCallback callback);

  // Utilities to get various AEADs by type.

  static const Aead EMPTY;
  static const Aead AES_128_GCM;
  static const Aead AES_192_GCM;
  static const Aead AES_256_GCM;
  static const Aead CHACHA20_POLY1305;
  static const Aead XCHACHA20_POLY1305;
  static const Aead AES_128_CTR_HMAC_SHA256;
  static const Aead AES_256_CTR_HMAC_SHA256;
  static const Aead AES_128_GCM_SIV;
  static const Aead AES_256_GCM_SIV;
  static const Aead AES_128_GCM_RANDNONCE;
  static const Aead AES_256_GCM_RANDNONCE;
  static const Aead AES_128_CCM_BLUETOOTH;
  static const Aead AES_128_CCM_BLUETOOTH_8;
  static const Aead AES_128_CCM_MATTER;
  static const Aead AES_128_EAX;
  static const Aead AES_256_EAX;

 private:
  const EVP_AEAD* aead_ = nullptr;
  const AeadInfo* info_ = nullptr;

  using AeadConstructor = const EVP_AEAD* (*)();
  static const std::unordered_map<AeadConstructor, AeadInfo> aeadIndex;
  static const Aead FromConstructor(AeadConstructor construct);
};

class AeadCtxPointer final {
 public:
  static AeadCtxPointer New(const Aead& aead, bool encrypt, const unsigned char* key = nullptr, size_t keyLen = 0,
                            size_t tagLen = EVP_AEAD_DEFAULT_TAG_LENGTH /* = 0 */);

  AeadCtxPointer() = default;
  explicit AeadCtxPointer(EVP_AEAD_CTX* ctx);
  AeadCtxPointer(AeadCtxPointer&& other) noexcept;
  AeadCtxPointer& operator=(AeadCtxPointer&& other) noexcept;
  NCRYPTO_DISALLOW_COPY(AeadCtxPointer)
  ~AeadCtxPointer();

  inline bool operator==(std::nullptr_t) const noexcept {
    return ctx_ == nullptr;
  }
  inline operator bool() const {
    return ctx_ != nullptr;
  }
  inline EVP_AEAD_CTX* get() const {
    return ctx_.get();
  }
  inline operator EVP_AEAD_CTX*() const {
    return ctx_.get();
  }
  void reset(EVP_AEAD_CTX* ctx = nullptr);
  EVP_AEAD_CTX* release();

  bool init(const Aead& aead, bool encrypt, const unsigned char* key = nullptr, size_t keyLen = 0,
            size_t tagLen = EVP_AEAD_DEFAULT_TAG_LENGTH /* = 0 */);

  // TODO(npaun): BoringSSL does not define NIDs for all AEADs.
  // Decide if we will even implement this method.
  // int getNid() const;

  bool encrypt(const Buffer<const unsigned char>& in, Buffer<unsigned char>& out, Buffer<unsigned char>& tag,
               const Buffer<const unsigned char>& nonce, const Buffer<const unsigned char>& aad);

  bool decrypt(const Buffer<const unsigned char>& in, Buffer<unsigned char>& out, const Buffer<const unsigned char>& tag,
               const Buffer<const unsigned char>& nonce, const Buffer<const unsigned char>& aad);

 private:
  DeleteFnPtr<EVP_AEAD_CTX, EVP_AEAD_CTX_free> ctx_;
};
} // namespace ncrypto

#endif // OPENSSL_IS_BORINGSSL
