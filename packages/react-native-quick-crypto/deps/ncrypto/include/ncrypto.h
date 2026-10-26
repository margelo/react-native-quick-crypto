#pragma once

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#ifdef OPENSSL_IS_BORINGSSL
#include <openssl/aead.h>
#endif

#include <cstddef>
#include <functional>
#include <list>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#if NCRYPTO_DEVELOPMENT_CHECKS
#include <iostream>
#endif

// The FIPS-related functions are only available
// when the OpenSSL itself was compiled with FIPS support.
#if defined(OPENSSL_FIPS) && OPENSSL_VERSION_MAJOR < 3
#include <openssl/fips.h>
#endif // OPENSSL_FIPS

// Define OPENSSL_WITH_PQC for post-quantum cryptography support
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
#define OPENSSL_WITH_PQC 1
#define EVP_PKEY_ML_KEM_512 NID_ML_KEM_512
#define EVP_PKEY_ML_KEM_768 NID_ML_KEM_768
#define EVP_PKEY_ML_KEM_1024 NID_ML_KEM_1024
#endif

#ifdef __GNUC__
#define NCRYPTO_MUST_USE_RESULT __attribute__((warn_unused_result))
#else
#define NCRYPTO_MUST_USE_RESULT
#endif

#ifdef OPENSSL_IS_BORINGSSL
// Boringssl has opted to use size_t for some size related
// APIs while Openssl is still using ints
using OPENSSL_SIZE_T = size_t;
#else
using OPENSSL_SIZE_T = int;
#endif

namespace ncrypto {

// ============================================================================
// Utility macros

inline bool EqualNoCase(const std::string_view a, const std::string_view b) {
  if (a.size() != b.size())
    return false;
  return std::equal(a.begin(), a.end(), b.begin(), b.end(), [](char a, char b) { return std::tolower(a) == std::tolower(b); });
}

#if NCRYPTO_DEVELOPMENT_CHECKS
#define NCRYPTO_STR(x) #x
#define NCRYPTO_REQUIRE(EXPR)                                                                                                              \
  {                                                                                                                                        \
    if (!(EXPR)) {                                                                                                                         \
      abort();                                                                                                                             \
    }                                                                                                                                      \
  }

#define NCRYPTO_FAIL(MESSAGE)                                                                                                              \
  do {                                                                                                                                     \
    std::cerr << "FAIL: " << (MESSAGE) << std::endl;                                                                                       \
    abort();                                                                                                                               \
  } while (0);
#define NCRYPTO_ASSERT_EQUAL(LHS, RHS, MESSAGE)                                                                                            \
  do {                                                                                                                                     \
    if (LHS != RHS) {                                                                                                                      \
      std::cerr << "Mismatch: '" << LHS << "' - '" << RHS << "'" << std::endl;                                                             \
      NCRYPTO_FAIL(MESSAGE);                                                                                                               \
    }                                                                                                                                      \
  } while (0);
#define NCRYPTO_ASSERT_TRUE(COND)                                                                                                          \
  do {                                                                                                                                     \
    if (!(COND)) {                                                                                                                         \
      std::cerr << "Assert at line " << __LINE__ << " of file " << __FILE__ << std::endl;                                                  \
      NCRYPTO_FAIL(NCRYPTO_STR(COND));                                                                                                     \
    }                                                                                                                                      \
  } while (0);
#else
#define NCRYPTO_FAIL(MESSAGE)
#define NCRYPTO_ASSERT_EQUAL(LHS, RHS, MESSAGE)
#define NCRYPTO_ASSERT_TRUE(COND)
#endif

#define NCRYPTO_DISALLOW_COPY(Name)                                                                                                        \
  Name(const Name&) = delete;                                                                                                              \
  Name& operator=(const Name&) = delete;
#define NCRYPTO_DISALLOW_MOVE(Name)                                                                                                        \
  Name(Name&&) = delete;                                                                                                                   \
  Name& operator=(Name&&) = delete;
#define NCRYPTO_DISALLOW_COPY_AND_MOVE(Name)                                                                                               \
  NCRYPTO_DISALLOW_COPY(Name)                                                                                                              \
  NCRYPTO_DISALLOW_MOVE(Name)
#define NCRYPTO_DISALLOW_NEW_DELETE()                                                                                                      \
  void* operator new(size_t) = delete;                                                                                                     \
  void operator delete(void*) = delete;

[[noreturn]] inline void unreachable() {
#ifdef __GNUC__
  __builtin_unreachable();
#elif defined(_MSC_VER)
  __assume(false);
#else
#endif
}

static constexpr int kX509NameFlagsMultiline =
    ASN1_STRFLGS_ESC_2253 | ASN1_STRFLGS_ESC_CTRL | ASN1_STRFLGS_UTF8_CONVERT | XN_FLAG_SEP_MULTILINE | XN_FLAG_FN_SN;

// ============================================================================
// Error handling utilities

// Capture the current OpenSSL Error Stack. The stack will be ordered such
// that the error currently at the top of the stack is at the end of the
// list and the error at the bottom of the stack is at the beginning.
class CryptoErrorList final {
 public:
  enum class Option { NONE, CAPTURE_ON_CONSTRUCT };
  CryptoErrorList(Option option = Option::CAPTURE_ON_CONSTRUCT);

  void capture();

  // Add an error message to the end of the stack.
  void add(std::string message);

  inline const std::string& peek_back() const {
    return errors_.back();
  }
  inline size_t size() const {
    return errors_.size();
  }
  inline bool empty() const {
    return errors_.empty();
  }

  inline auto begin() const noexcept {
    return errors_.begin();
  }
  inline auto end() const noexcept {
    return errors_.end();
  }
  inline auto rbegin() const noexcept {
    return errors_.rbegin();
  }
  inline auto rend() const noexcept {
    return errors_.rend();
  }

  std::optional<std::string> pop_back();
  std::optional<std::string> pop_front();

 private:
  std::list<std::string> errors_;
};

// Forcibly clears the error stack on destruction. This stops stale errors
// from popping up later in the lifecycle of crypto operations where they
// would cause spurious failures. It is a rather blunt method, though, and
// ERR_clear_error() isn't necessarily cheap.
//
// If created with a pointer to a CryptoErrorList, the current OpenSSL error
// stack will be captured before clearing the error.
class ClearErrorOnReturn final {
 public:
  ClearErrorOnReturn(CryptoErrorList* errors = nullptr);
  ~ClearErrorOnReturn();
  NCRYPTO_DISALLOW_COPY_AND_MOVE(ClearErrorOnReturn)
  NCRYPTO_DISALLOW_NEW_DELETE()

  int peekError();

 private:
  CryptoErrorList* errors_;
};

// Pop errors from OpenSSL's error stack that were added between when this
// was constructed and destructed.
//
// If created with a pointer to a CryptoErrorList, the current OpenSSL error
// stack will be captured before resetting the error to the mark.
class MarkPopErrorOnReturn final {
 public:
  MarkPopErrorOnReturn(CryptoErrorList* errors = nullptr);
  ~MarkPopErrorOnReturn();
  NCRYPTO_DISALLOW_COPY_AND_MOVE(MarkPopErrorOnReturn)
  NCRYPTO_DISALLOW_NEW_DELETE()

  int peekError();

 private:
  CryptoErrorList* errors_;
};

// TODO(@jasnell): Eventually replace with std::expected when we are able to
// bump up to c++23.
template <typename T, typename E>
struct Result final {
  const bool has_value;
  T value;
  std::optional<E> error = std::nullopt;
  std::optional<int> openssl_error = std::nullopt;
  Result(T&& value) : has_value(true), value(std::move(value)) {}
  Result(E&& error, std::optional<int> openssl_error = std::nullopt)
      : has_value(false), error(std::move(error)), openssl_error(std::move(openssl_error)) {}
  inline operator bool() const {
    return has_value;
  }
};

// ============================================================================
// Various smart pointer aliases for OpenSSL types.

template <typename T, void (*function)(T*)>
struct FunctionDeleter {
  void operator()(T* pointer) const {
    function(pointer);
  }
  typedef std::unique_ptr<T, FunctionDeleter> Pointer;
};

template <typename T, void (*function)(T*)>
using DeleteFnPtr = typename FunctionDeleter<T, function>::Pointer;

using PKCS8Pointer = DeleteFnPtr<PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_free>;

class BIOPointer;
class BignumPointer;
class CipherCtxPointer;
class DataPointer;
class EVPKeyPointer;
class EVPMacCtxPointer;
class EVPMacPointer;
class EVPMDCtxPointer;
class X509View;
class X509Pointer;
class ECDSASigPointer;

struct StackOfXASN1Deleter {
  void operator()(STACK_OF(ASN1_OBJECT) * p) const {
    sk_ASN1_OBJECT_pop_free(p, ASN1_OBJECT_free);
  }
};
using StackOfASN1 = std::unique_ptr<STACK_OF(ASN1_OBJECT), StackOfXASN1Deleter>;

// An unowned, unmanaged pointer to a buffer of data.
template <typename T>
struct Buffer {
  T* data = nullptr;
  size_t len = 0;
};

class Digest final {
 public:
  static constexpr size_t MAX_SIZE = EVP_MAX_MD_SIZE;
  Digest() = default;
  Digest(const EVP_MD* md) : md_(md) {}
  Digest(const Digest&) = default;
  Digest& operator=(const Digest&) = default;
  inline Digest& operator=(const EVP_MD* md) {
    md_ = md;
    return *this;
  }
  NCRYPTO_DISALLOW_MOVE(Digest)

  size_t size() const;

  inline const EVP_MD* get() const {
    return md_;
  }
  inline operator const EVP_MD*() const {
    return md_;
  }
  inline operator bool() const {
    return md_ != nullptr;
  }

  static const Digest MD5;
  static const Digest SHA1;
  static const Digest SHA256;
  static const Digest SHA384;
  static const Digest SHA512;

  static const Digest FromName(const char* name);

 private:
  const EVP_MD* md_ = nullptr;
};

// Computes a fixed-length digest.
DataPointer hashDigest(const Buffer<const unsigned char>& data, const EVP_MD* md);
// Computes a variable-length digest for XOF algorithms (e.g. SHAKE128).
DataPointer xofHashDigest(const Buffer<const unsigned char>& data, const EVP_MD* md, size_t length);

class Cipher final {
 public:
  static constexpr size_t MAX_KEY_LENGTH = EVP_MAX_KEY_LENGTH;
  static constexpr size_t MAX_IV_LENGTH = EVP_MAX_IV_LENGTH;
#ifdef EVP_MAX_AEAD_TAG_LENGTH
  static constexpr size_t MAX_AUTH_TAG_LENGTH = EVP_MAX_AEAD_TAG_LENGTH;
#else
  static constexpr size_t MAX_AUTH_TAG_LENGTH = 16;
#endif
  static_assert(EVP_GCM_TLS_TAG_LEN <= MAX_AUTH_TAG_LENGTH
#ifndef OPENSSL_IS_BORINGSSL
                && EVP_CCM_TLS_TAG_LEN <= MAX_AUTH_TAG_LENGTH && EVP_CHACHAPOLY_TLS_TAG_LEN <= MAX_AUTH_TAG_LENGTH
#endif
  );

  Cipher() = default;
  Cipher(const EVP_CIPHER* cipher) : cipher_(cipher) {}
  Cipher(const Cipher&) = default;
  Cipher& operator=(const Cipher&) = default;
  inline Cipher& operator=(const EVP_CIPHER* cipher) {
    cipher_ = cipher;
    return *this;
  }
  NCRYPTO_DISALLOW_MOVE(Cipher)

  inline const EVP_CIPHER* get() const {
    return cipher_;
  }
  inline operator const EVP_CIPHER*() const {
    return cipher_;
  }
  inline operator bool() const {
    return cipher_ != nullptr;
  }

  int getNid() const;
  int getMode() const;
  int getIvLength() const;
  int getKeyLength() const;
  int getBlockSize() const;
  std::string_view getModeLabel() const;
  const char* getName() const;

  bool isGcmMode() const;
  bool isWrapMode() const;
  bool isCtrMode() const;
  bool isCcmMode() const;
  bool isOcbMode() const;
  bool isStreamMode() const;
  bool isChaCha20Poly1305() const;

  bool isSupportedAuthenticatedMode() const;

  int bytesToKey(const Digest& digest, const Buffer<const unsigned char>& input, unsigned char* key, unsigned char* iv) const;

  static const Cipher FromName(const char* name);
  static const Cipher FromNid(int nid);
  static const Cipher FromCtx(const CipherCtxPointer& ctx);

  using CipherNameCallback = std::function<void(const char* name)>;

  // Iterates the known ciphers if the underlying implementation
  // is able to do so.
  static void ForEach(CipherNameCallback callback);

  // Utilities to get various ciphers by type. If the underlying
  // implementation does not support the requested cipher, then
  // the result will be an empty Cipher object whose bool operator
  // will return false.

  static const Cipher EMPTY;
  static const Cipher AES_128_CBC;
  static const Cipher AES_192_CBC;
  static const Cipher AES_256_CBC;
  static const Cipher AES_128_CTR;
  static const Cipher AES_192_CTR;
  static const Cipher AES_256_CTR;
  static const Cipher AES_128_GCM;
  static const Cipher AES_192_GCM;
  static const Cipher AES_256_GCM;
  static const Cipher AES_128_KW;
  static const Cipher AES_192_KW;
  static const Cipher AES_256_KW;
  static const Cipher AES_128_OCB;
  static const Cipher AES_192_OCB;
  static const Cipher AES_256_OCB;
  static const Cipher CHACHA20_POLY1305;

  struct CipherParams {
    int padding;
    Digest digest;
    const Buffer<const void> label;
  };

  static DataPointer encrypt(const EVPKeyPointer& key, const CipherParams& params, const Buffer<const void> in);
  static DataPointer decrypt(const EVPKeyPointer& key, const CipherParams& params, const Buffer<const void> in);

  static DataPointer sign(const EVPKeyPointer& key, const CipherParams& params, const Buffer<const void> in);

  static DataPointer recover(const EVPKeyPointer& key, const CipherParams& params, const Buffer<const void> in);

  static constexpr bool IsValidGCMTagLength(unsigned int tag_len) {
    return tag_len == 4 || tag_len == 8 || (tag_len >= 12 && tag_len <= 16);
  }

 private:
  const EVP_CIPHER* cipher_ = nullptr;
};

class BignumPointer final {
 public:
  BignumPointer() = default;
  explicit BignumPointer(BIGNUM* bignum);
  explicit BignumPointer(const unsigned char* data, size_t len);
  BignumPointer(BignumPointer&& other) noexcept;
  BignumPointer& operator=(BignumPointer&& other) noexcept;
  NCRYPTO_DISALLOW_COPY(BignumPointer)
  ~BignumPointer();

  int operator<=>(const BignumPointer& other) const noexcept;
  int operator<=>(const BIGNUM* other) const noexcept;
  inline operator bool() const {
    return bn_ != nullptr;
  }
  inline BIGNUM* get() const noexcept {
    return bn_.get();
  }
  void reset(BIGNUM* bn = nullptr);
  void reset(const unsigned char* data, size_t len);
  BIGNUM* release();

  bool isZero() const;
  bool isOne() const;

  bool setWord(unsigned long w); // NOLINT(runtime/int)
  unsigned long getWord() const; // NOLINT(runtime/int)

  size_t byteLength() const;
  size_t bitLength() const;

  DataPointer toHex() const;
  DataPointer encode() const;
  DataPointer encodePadded(size_t size) const;
  size_t encodeInto(unsigned char* out) const;
  size_t encodePaddedInto(unsigned char* out, size_t size) const;

  using PrimeCheckCallback = std::function<bool(int, int)>;
  int isPrime(int checks, PrimeCheckCallback cb = defaultPrimeCheckCallback) const;
  struct PrimeConfig {
    int bits;
    bool safe = false;
    const BignumPointer& add;
    const BignumPointer& rem;
  };

  static BignumPointer NewPrime(const PrimeConfig& params, PrimeCheckCallback cb = defaultPrimeCheckCallback);

  bool generate(const PrimeConfig& params, PrimeCheckCallback cb = defaultPrimeCheckCallback) const;

  static BignumPointer New();
  static BignumPointer NewSecure();
  static BignumPointer NewSub(const BignumPointer& a, const BignumPointer& b);
  static BignumPointer NewLShift(size_t length);

  static DataPointer Encode(const BIGNUM* bn);
  static DataPointer EncodePadded(const BIGNUM* bn, size_t size);
  static size_t EncodePaddedInto(const BIGNUM* bn, unsigned char* out, size_t size);
  static int GetBitCount(const BIGNUM* bn);
  static int GetByteCount(const BIGNUM* bn);
  static unsigned long GetWord(const BIGNUM* bn); // NOLINT(runtime/int)
  static const BIGNUM* One();

  BignumPointer clone();

 private:
  DeleteFnPtr<BIGNUM, BN_clear_free> bn_;

  static bool defaultPrimeCheckCallback(int, int) {
    return 1;
  }
};

// A managed pointer to a buffer of data. When destroyed the underlying
// buffer will be freed.
class DataPointer final {
 public:
  static DataPointer Alloc(size_t len);
  static DataPointer Copy(const Buffer<const void>& buffer);

  // Attempts to allocate the buffer space using the secure heap, if
  // supported/enabled. If the secure heap is disabled, then this
  // ends up being equivalent to Alloc(len). Note that allocation
  // will fail if there is not enough free space remaining in the
  // secure heap space.
  static DataPointer SecureAlloc(size_t len);

  // If the secure heap is enabled, returns the amount of data that
  // has been allocated from the heap.
  static size_t GetSecureHeapUsed();

  enum class InitSecureHeapResult {
    FAILED,
    UNABLE_TO_MEMORY_MAP,
    OK,
  };

  // Attempt to initialize the secure heap. The secure heap is not
  // supported on all operating systems and whenever boringssl is
  // used.
  static InitSecureHeapResult TryInitSecureHeap(size_t amount, size_t min);

  DataPointer() = default;
  explicit DataPointer(void* data, size_t len, bool secure = false);
  explicit DataPointer(const Buffer<void>& buffer, bool secure = false);
  DataPointer(DataPointer&& other) noexcept;
  DataPointer& operator=(DataPointer&& other) noexcept;
  NCRYPTO_DISALLOW_COPY(DataPointer)
  ~DataPointer();

  inline bool operator==(std::nullptr_t) noexcept {
    return data_ == nullptr;
  }
  inline operator bool() const {
    return data_ != nullptr;
  }

  template <typename T = void>
  inline T* get() const noexcept {
    return static_cast<T*>(data_);
  }

  inline size_t size() const noexcept {
    return len_;
  }
  void reset(void* data = nullptr, size_t len = 0);
  void reset(const Buffer<void>& buffer);

  // Sets the underlying data buffer to all zeros.
  void zero();

  DataPointer resize(size_t len);

  // Releases ownership of the underlying data buffer. It is the caller's
  // responsibility to ensure the buffer is appropriately freed.
  Buffer<void> release();

  // Returns a Buffer struct that is a view of the underlying data.
  template <typename T = void>
  inline operator const Buffer<T>() const {
    return {
        .data = static_cast<T*>(data_),
        .len = len_,
    };
  }

  bool isSecure() const {
    return secure_;
  }

 private:
  void free();

  void* data_ = nullptr;
  size_t len_ = 0;
  bool secure_ = false;
};

class BIOPointer final {
 public:
  static BIOPointer NewMem();
  static BIOPointer NewSecMem();
  static BIOPointer New(const BIO_METHOD* method);
  static BIOPointer New(const void* data, size_t len);
  static BIOPointer New(const BIGNUM* bn);
  static BIOPointer NewFile(const char* filename, const char* mode);
  static BIOPointer NewFp(FILE* fd, int flags);

  template <typename T>
  static BIOPointer New(const Buffer<T>& buf) {
    return New(buf.data, buf.len);
  }

  BIOPointer() = default;
  BIOPointer(std::nullptr_t) : bio_(nullptr) {}
  explicit BIOPointer(BIO* bio);
  BIOPointer(BIOPointer&& other) noexcept;
  BIOPointer& operator=(BIOPointer&& other) noexcept;
  NCRYPTO_DISALLOW_COPY(BIOPointer)
  ~BIOPointer();

  inline bool operator==(std::nullptr_t) noexcept {
    return bio_ == nullptr;
  }
  inline operator bool() const {
    return bio_ != nullptr;
  }
  inline BIO* get() const noexcept {
    return bio_.get();
  }

  inline operator BUF_MEM*() const {
    BUF_MEM* mem = nullptr;
    if (!bio_)
      return mem;
    BIO_get_mem_ptr(bio_.get(), &mem);
    return mem;
  }

  inline operator BIO*() const {
    return bio_.get();
  }

  void reset(BIO* bio = nullptr);
  BIO* release();

  bool resetBio() const;

  static int Write(BIOPointer* bio, std::string_view message);

  template <typename... Args>
  static void Printf(BIOPointer* bio, const char* format, Args... args) {
    if (bio == nullptr || !*bio)
      return;
    BIO_printf(bio->get(), format, std::forward<Args...>(args...));
  }

 private:
  mutable DeleteFnPtr<BIO, BIO_free_all> bio_;
};

class CipherCtxPointer final {
 public:
  static CipherCtxPointer New();

  CipherCtxPointer() = default;
  explicit CipherCtxPointer(EVP_CIPHER_CTX* ctx);
  CipherCtxPointer(CipherCtxPointer&& other) noexcept;
  CipherCtxPointer& operator=(CipherCtxPointer&& other) noexcept;
  NCRYPTO_DISALLOW_COPY(CipherCtxPointer)
  ~CipherCtxPointer();

  inline bool operator==(std::nullptr_t) const noexcept {
    return ctx_ == nullptr;
  }
  inline operator bool() const {
    return ctx_ != nullptr;
  }
  inline EVP_CIPHER_CTX* get() const {
    return ctx_.get();
  }
  inline operator EVP_CIPHER_CTX*() const {
    return ctx_.get();
  }
  void reset(EVP_CIPHER_CTX* ctx = nullptr);
  EVP_CIPHER_CTX* release();

  void setAllowWrap();

  bool setKeyLength(size_t length);
  bool setIvLength(size_t length);
  bool setAeadTag(const Buffer<const char>& tag);
  bool setAeadTagLength(size_t length);
  bool setPadding(bool padding);
  bool init(const Cipher& cipher, bool encrypt, const unsigned char* key = nullptr, const unsigned char* iv = nullptr);

  int getBlockSize() const;
  int getMode() const;
  int getNid() const;

  bool isGcmMode() const;
  bool isOcbMode() const;
  bool isCcmMode() const;
  bool isWrapMode() const;
  bool isChaCha20Poly1305() const;

  bool update(const Buffer<const unsigned char>& in, unsigned char* out, int* out_len, bool finalize = false);
  bool getAeadTag(size_t len, unsigned char* out);

 private:
  DeleteFnPtr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free> ctx_;
};

class EVPKeyCtxPointer final {
 public:
  EVPKeyCtxPointer();
  explicit EVPKeyCtxPointer(EVP_PKEY_CTX* ctx);
  EVPKeyCtxPointer(EVPKeyCtxPointer&& other) noexcept;
  EVPKeyCtxPointer& operator=(EVPKeyCtxPointer&& other) noexcept;
  NCRYPTO_DISALLOW_COPY(EVPKeyCtxPointer)
  ~EVPKeyCtxPointer();

  inline bool operator==(std::nullptr_t) const noexcept {
    return ctx_ == nullptr;
  }
  inline operator bool() const {
    return ctx_ != nullptr;
  }
  inline EVP_PKEY_CTX* get() const {
    return ctx_.get();
  }
  void reset(EVP_PKEY_CTX* ctx = nullptr);
  EVP_PKEY_CTX* release();

  bool initForDerive(const EVPKeyPointer& peer);
  DataPointer derive() const;

  bool initForParamgen();
  bool setDhParameters(int prime_size, uint32_t generator);
  bool setDsaParameters(uint32_t bits, std::optional<int> q_bits);
  bool setEcParameters(int curve, int encoding);

  bool setRsaOaepMd(const Digest& md);
  bool setRsaMgf1Md(const Digest& md);
  bool setRsaPadding(int padding);
  bool setRsaKeygenPubExp(BignumPointer&& e);
  bool setRsaKeygenBits(int bits);
  bool setRsaPssKeygenMd(const Digest& md);
  bool setRsaPssKeygenMgf1Md(const Digest& md);
  bool setRsaPssSaltlen(int salt_len);
  bool setRsaImplicitRejection();
  bool setRsaOaepLabel(DataPointer&& data);

  bool setSignatureMd(const EVPMDCtxPointer& md);

  bool publicCheck() const;
  bool privateCheck() const;

  bool verify(const Buffer<const unsigned char>& sig, const Buffer<const unsigned char>& data);
  DataPointer sign(const Buffer<const unsigned char>& data);
  bool signInto(const Buffer<const unsigned char>& data, Buffer<unsigned char>* sig);

  static constexpr int kDefaultRsaExponent = 0x10001;

  static bool setRsaPadding(EVP_PKEY_CTX* ctx, int padding, std::optional<int> salt_len = std::nullopt);

  EVPKeyPointer paramgen() const;

  bool initForEncrypt();
  bool initForDecrypt();
  bool initForKeygen();
  int initForVerify();
  int initForSign();

  static EVPKeyCtxPointer New(const EVPKeyPointer& key);
  static EVPKeyCtxPointer NewFromID(int id);

 private:
  DeleteFnPtr<EVP_PKEY_CTX, EVP_PKEY_CTX_free> ctx_;
};

class EVPKeyPointer final {
 public:
  static EVPKeyPointer New();
  static EVPKeyPointer NewRawPublic(int id, const Buffer<const unsigned char>& data);
  static EVPKeyPointer NewRawPrivate(int id, const Buffer<const unsigned char>& data);
#if OPENSSL_WITH_PQC
  static EVPKeyPointer NewRawSeed(int id, const Buffer<const unsigned char>& data);
#endif
  enum class PKEncodingType {
    // RSAPublicKey / RSAPrivateKey according to PKCS#1.
    PKCS1,
    // PrivateKeyInfo or EncryptedPrivateKeyInfo according to PKCS#8.
    PKCS8,
    // SubjectPublicKeyInfo according to X.509.
    SPKI,
    // ECPrivateKey according to SEC1.
    SEC1,
  };

  enum class PKFormatType {
    DER,
    PEM,
    JWK,
    RAW_PUBLIC,
    RAW_PRIVATE,
    RAW_SEED,
  };

  enum class PKParseError { NOT_RECOGNIZED, NEED_PASSPHRASE, FAILED };
  using ParseKeyResult = Result<EVPKeyPointer, PKParseError>;

  struct AsymmetricKeyEncodingConfig {
    bool output_key_object = false;
    PKFormatType format = PKFormatType::DER;
    PKEncodingType type = PKEncodingType::PKCS8;
    int ec_point_form = POINT_CONVERSION_UNCOMPRESSED;
    AsymmetricKeyEncodingConfig() = default;
    AsymmetricKeyEncodingConfig(bool output_key_object, PKFormatType format, PKEncodingType type);
    AsymmetricKeyEncodingConfig(const AsymmetricKeyEncodingConfig&) = default;
    AsymmetricKeyEncodingConfig& operator=(const AsymmetricKeyEncodingConfig&) = default;
  };
  using PublicKeyEncodingConfig = AsymmetricKeyEncodingConfig;

  struct PrivateKeyEncodingConfig : public AsymmetricKeyEncodingConfig {
    const EVP_CIPHER* cipher = nullptr;
    std::optional<DataPointer> passphrase = std::nullopt;
    PrivateKeyEncodingConfig() = default;
    PrivateKeyEncodingConfig(bool output_key_object, PKFormatType format, PKEncodingType type)
        : AsymmetricKeyEncodingConfig(output_key_object, format, type) {}
    PrivateKeyEncodingConfig(const PrivateKeyEncodingConfig&);
    PrivateKeyEncodingConfig& operator=(const PrivateKeyEncodingConfig&);
  };

  static ParseKeyResult TryParsePublicKey(const PublicKeyEncodingConfig& config, const Buffer<const unsigned char>& buffer);

  static ParseKeyResult TryParsePublicKeyPEM(const Buffer<const unsigned char>& buffer);

  static ParseKeyResult TryParsePrivateKey(const PrivateKeyEncodingConfig& config, const Buffer<const unsigned char>& buffer);

  EVPKeyPointer() = default;
  explicit EVPKeyPointer(EVP_PKEY* pkey);
  EVPKeyPointer(EVPKeyPointer&& other) noexcept;
  EVPKeyPointer& operator=(EVPKeyPointer&& other) noexcept;
  NCRYPTO_DISALLOW_COPY(EVPKeyPointer)
  ~EVPKeyPointer();

  inline bool operator==(std::nullptr_t) const noexcept {
    return pkey_ == nullptr;
  }
  inline operator bool() const {
    return pkey_ != nullptr;
  }
  inline EVP_PKEY* get() const {
    return pkey_.get();
  }
  void reset(EVP_PKEY* pkey = nullptr);
  EVP_PKEY* release();

  static int id(const EVP_PKEY* key);
  static int base_id(const EVP_PKEY* key);

  int id() const;
  int base_id() const;
  int bits() const;
  size_t size() const;

  size_t rawPublicKeySize() const;
  size_t rawPrivateKeySize() const;
  DataPointer rawPublicKey() const;
  DataPointer rawPrivateKey() const;
  BIOPointer derPublicKey() const;

#if OPENSSL_WITH_PQC
  DataPointer rawSeed() const;
#endif

  Result<BIOPointer, bool> writePrivateKey(const PrivateKeyEncodingConfig& config) const;
  Result<BIOPointer, bool> writePublicKey(const PublicKeyEncodingConfig& config) const;

  EVPKeyCtxPointer newCtx() const;

  static bool IsRSAPrivateKey(const Buffer<const unsigned char>& buffer);

  std::optional<uint32_t> getBytesOfRS() const;
  int getDefaultSignPadding() const;
  bool isRsaVariant() const;
  bool isOneShotVariant() const;
  bool isSigVariant() const;
  bool validateDsaParameters() const;

  EVPKeyPointer clone() const;

 private:
  DeleteFnPtr<EVP_PKEY, EVP_PKEY_free> pkey_;
};

class X509View final {
 public:
  X509View() = default;
  inline explicit X509View(const X509* cert) : cert_(cert) {}
  X509View(const X509View& other) = default;
  X509View& operator=(const X509View& other) = default;
  NCRYPTO_DISALLOW_MOVE(X509View)

  inline X509* get() const {
    return const_cast<X509*>(cert_);
  }
  inline operator X509*() const {
    return const_cast<X509*>(cert_);
  }
  inline operator const X509*() const {
    return cert_;
  }

  inline bool operator==(std::nullptr_t) noexcept {
    return cert_ == nullptr;
  }
  inline operator bool() const {
    return cert_ != nullptr;
  }

  BIOPointer toPEM() const;
  BIOPointer toDER() const;

  BIOPointer getSubject() const;
  BIOPointer getSubjectAltName() const;
  BIOPointer getIssuer() const;
  BIOPointer getInfoAccess() const;
  BIOPointer getValidFrom() const;
  BIOPointer getValidTo() const;
  std::optional<std::string_view> getSignatureAlgorithm() const;
  std::optional<std::string> getSignatureAlgorithmOID() const;
  int64_t getValidFromTime() const;
  int64_t getValidToTime() const;
  DataPointer getSerialNumber() const;
  Result<EVPKeyPointer, int> getPublicKey() const;
  StackOfASN1 getKeyUsage() const;

  bool isCA() const;
  bool isIssuedBy(const X509View& other) const;
  bool checkPrivateKey(const EVPKeyPointer& pkey) const;
  bool checkPublicKey(const EVPKeyPointer& pkey) const;

  std::optional<std::string> getFingerprint(const Digest& method) const;

  enum class CheckMatch {
    NO_MATCH,
    MATCH,
    INVALID_NAME,
    OPERATION_FAILED,
  };
  CheckMatch checkHost(std::string_view host, int flags, DataPointer* peerName = nullptr) const;
  CheckMatch checkEmail(std::string_view email, int flags) const;
  CheckMatch checkIp(std::string_view ip, int flags) const;

  using UsageCallback = std::function<void(const char*)>;
  bool enumUsages(UsageCallback callback) const;

 private:
  const X509* cert_ = nullptr;
};

class X509Pointer final {
 public:
  static Result<X509Pointer, int> Parse(Buffer<const unsigned char> buffer);
  X509Pointer() = default;
  explicit X509Pointer(X509* cert);
  X509Pointer(X509Pointer&& other) noexcept;
  X509Pointer& operator=(X509Pointer&& other) noexcept;
  NCRYPTO_DISALLOW_COPY(X509Pointer)
  ~X509Pointer();

  inline bool operator==(std::nullptr_t) noexcept {
    return cert_ == nullptr;
  }
  inline operator bool() const {
    return cert_ != nullptr;
  }
  inline X509* get() const {
    return cert_.get();
  }
  inline operator X509*() const {
    return cert_.get();
  }
  inline operator const X509*() const {
    return cert_.get();
  }
  void reset(X509* cert = nullptr);
  X509* release();

  X509View view() const;
  operator X509View() const {
    return view();
  }

  static const char* ErrorCode(int32_t err);
  static std::optional<const char*> ErrorReason(int32_t err);

 private:
  DeleteFnPtr<X509, X509_free> cert_;
};

class ECDSASigPointer final {
 public:
  explicit ECDSASigPointer();
  explicit ECDSASigPointer(ECDSA_SIG* sig);
  ECDSASigPointer(ECDSASigPointer&& other) noexcept;
  ECDSASigPointer& operator=(ECDSASigPointer&& other) noexcept;
  NCRYPTO_DISALLOW_COPY(ECDSASigPointer)
  ~ECDSASigPointer();

  inline bool operator==(std::nullptr_t) noexcept {
    return sig_ == nullptr;
  }
  inline operator bool() const {
    return sig_ != nullptr;
  }
  inline ECDSA_SIG* get() const {
    return sig_.get();
  }
  inline operator ECDSA_SIG*() const {
    return sig_.get();
  }
  void reset(ECDSA_SIG* sig = nullptr);
  ECDSA_SIG* release();

  static ECDSASigPointer New();
  static ECDSASigPointer Parse(const Buffer<const unsigned char>& buffer);

  inline const BIGNUM* r() const {
    return pr_;
  }
  inline const BIGNUM* s() const {
    return ps_;
  }

  bool setParams(BignumPointer&& r, BignumPointer&& s);

  Buffer<unsigned char> encode() const;

 private:
  DeleteFnPtr<ECDSA_SIG, ECDSA_SIG_free> sig_;
  const BIGNUM* pr_ = nullptr;
  const BIGNUM* ps_ = nullptr;
};

class EVPMDCtxPointer final {
 public:
  EVPMDCtxPointer();
  explicit EVPMDCtxPointer(EVP_MD_CTX* ctx);
  EVPMDCtxPointer(EVPMDCtxPointer&& other) noexcept;
  EVPMDCtxPointer& operator=(EVPMDCtxPointer&& other) noexcept;
  NCRYPTO_DISALLOW_COPY(EVPMDCtxPointer)
  ~EVPMDCtxPointer();

  inline bool operator==(std::nullptr_t) noexcept {
    return ctx_ == nullptr;
  }
  inline operator bool() const {
    return ctx_ != nullptr;
  }
  inline EVP_MD_CTX* get() const {
    return ctx_.get();
  }
  inline operator EVP_MD_CTX*() const {
    return ctx_.get();
  }
  void reset(EVP_MD_CTX* ctx = nullptr);
  EVP_MD_CTX* release();

  bool digestInit(const Digest& digest);
  bool digestUpdate(const Buffer<const void>& in);
  DataPointer digestFinal(size_t length);
  bool digestFinalInto(Buffer<void>* buf);
  size_t getExpectedSize();

  std::optional<EVP_PKEY_CTX*> signInit(const EVPKeyPointer& key, const Digest& digest);
  std::optional<EVP_PKEY_CTX*> verifyInit(const EVPKeyPointer& key, const Digest& digest);

  std::optional<EVP_PKEY_CTX*> signInitWithContext(const EVPKeyPointer& key, const Digest& digest,
                                                   const Buffer<const unsigned char>& context_string);
  std::optional<EVP_PKEY_CTX*> verifyInitWithContext(const EVPKeyPointer& key, const Digest& digest,
                                                     const Buffer<const unsigned char>& context_string);

  DataPointer signOneShot(const Buffer<const unsigned char>& buf) const;
  DataPointer sign(const Buffer<const unsigned char>& buf) const;
  bool verify(const Buffer<const unsigned char>& buf, const Buffer<const unsigned char>& sig) const;

  const EVP_MD* getDigest() const;
  size_t getDigestSize() const;
  bool hasXofFlag() const;

  bool copyTo(const EVPMDCtxPointer& other) const;

  static EVPMDCtxPointer New();

 private:
  DeleteFnPtr<EVP_MD_CTX, EVP_MD_CTX_free> ctx_;
};

#if OPENSSL_VERSION_MAJOR >= 3
class EVPMacPointer final {
 public:
  EVPMacPointer() = default;
  explicit EVPMacPointer(EVP_MAC* mac);
  EVPMacPointer(EVPMacPointer&& other) noexcept;
  EVPMacPointer& operator=(EVPMacPointer&& other) noexcept;
  NCRYPTO_DISALLOW_COPY(EVPMacPointer)
  ~EVPMacPointer();

  inline bool operator==(std::nullptr_t) noexcept {
    return mac_ == nullptr;
  }
  inline operator bool() const {
    return mac_ != nullptr;
  }
  inline EVP_MAC* get() const {
    return mac_.get();
  }
  inline operator EVP_MAC*() const {
    return mac_.get();
  }
  void reset(EVP_MAC* mac = nullptr);
  EVP_MAC* release();

  static EVPMacPointer Fetch(const char* algorithm);

 private:
  DeleteFnPtr<EVP_MAC, EVP_MAC_free> mac_;
};

class EVPMacCtxPointer final {
 public:
  EVPMacCtxPointer() = default;
  explicit EVPMacCtxPointer(EVP_MAC_CTX* ctx);
  EVPMacCtxPointer(EVPMacCtxPointer&& other) noexcept;
  EVPMacCtxPointer& operator=(EVPMacCtxPointer&& other) noexcept;
  NCRYPTO_DISALLOW_COPY(EVPMacCtxPointer)
  ~EVPMacCtxPointer();

  inline bool operator==(std::nullptr_t) noexcept {
    return ctx_ == nullptr;
  }
  inline operator bool() const {
    return ctx_ != nullptr;
  }
  inline EVP_MAC_CTX* get() const {
    return ctx_.get();
  }
  inline operator EVP_MAC_CTX*() const {
    return ctx_.get();
  }
  void reset(EVP_MAC_CTX* ctx = nullptr);
  EVP_MAC_CTX* release();

  bool init(const Buffer<const void>& key, const OSSL_PARAM* params = nullptr);
  bool update(const Buffer<const void>& data);
  DataPointer final(size_t length);

  static EVPMacCtxPointer New(EVP_MAC* mac);

 private:
  DeleteFnPtr<EVP_MAC_CTX, EVP_MAC_CTX_free> ctx_;
};
#endif // OPENSSL_VERSION_MAJOR >= 3

// ============================================================================
// FIPS
bool isFipsEnabled();

bool setFipsEnabled(bool enabled, CryptoErrorList* errors);

bool testFipsEnabled();

// ============================================================================
// Various utilities

bool CSPRNG(void* buffer, size_t length) NCRYPTO_MUST_USE_RESULT;

// This callback is used to avoid the default passphrase callback in OpenSSL
// which will typically prompt for the passphrase. The prompting is designed
// for the OpenSSL CLI, but works poorly for some environments like Node.js
// because it involves synchronous interaction with the controlling terminal,
// something we never want, and use this function to avoid it.
int NoPasswordCallback(char* buf, int size, int rwflag, void* u);

int PasswordCallback(char* buf, int size, int rwflag, void* u);

bool SafeX509SubjectAltNamePrint(const BIOPointer& out, const X509_EXTENSION* ext);
bool SafeX509InfoAccessPrint(const BIOPointer& out, const X509_EXTENSION* ext);

// ============================================================================
// SPKAC

bool VerifySpkac(const char* input, size_t length);
BIOPointer ExportPublicKey(const char* input, size_t length);

// The caller takes ownership of the returned Buffer<char>
Buffer<char> ExportChallenge(const char* input, size_t length);

bool VerifySpkac(const Buffer<const char>& buf);
BIOPointer ExportPublicKey(const Buffer<const char>& buf);
DataPointer ExportChallenge(const Buffer<const char>& buf);

// ============================================================================
// KDF

const EVP_MD* getDigestByName(const char* name);
const EVP_CIPHER* getCipherByName(const char* name);

// Verify that the specified HKDF output length is valid for the given digest.
// The maximum length for HKDF output for a given digest is 255 times the
// hash size for the given digest algorithm.
bool checkHkdfLength(const Digest& digest, size_t length);

bool extractP1363(const Buffer<const unsigned char>& buf, unsigned char* dest, size_t n);

bool hkdfInfo(const Digest& md, const Buffer<const unsigned char>& key, const Buffer<const unsigned char>& info,
              const Buffer<const unsigned char>& salt, size_t length, Buffer<unsigned char>* out);

DataPointer hkdf(const Digest& md, const Buffer<const unsigned char>& key, const Buffer<const unsigned char>& info,
                 const Buffer<const unsigned char>& salt, size_t length);

bool checkScryptParams(uint64_t N, uint64_t r, uint64_t p, uint64_t maxmem);

bool scryptInto(const Buffer<const char>& pass, const Buffer<const unsigned char>& salt, uint64_t N, uint64_t r, uint64_t p,
                uint64_t maxmem, size_t length, Buffer<unsigned char>* out);

DataPointer scrypt(const Buffer<const char>& pass, const Buffer<const unsigned char>& salt, uint64_t N, uint64_t r, uint64_t p,
                   uint64_t maxmem, size_t length);

bool pbkdf2Into(const Digest& md, const Buffer<const char>& pass, const Buffer<const unsigned char>& salt, uint32_t iterations,
                size_t length, Buffer<unsigned char>* out);

DataPointer pbkdf2(const Digest& md, const Buffer<const char>& pass, const Buffer<const unsigned char>& salt, uint32_t iterations,
                   size_t length);

#if OPENSSL_VERSION_NUMBER >= 0x30200000L
#ifndef OPENSSL_NO_ARGON2
enum class Argon2Type { ARGON2D, ARGON2I, ARGON2ID };

DataPointer argon2(const Buffer<const char>& pass, const Buffer<const unsigned char>& salt, uint32_t lanes, size_t length, uint32_t memcost,
                   uint32_t iter, uint32_t version, const Buffer<const unsigned char>& secret, const Buffer<const unsigned char>& ad,
                   Argon2Type type);
#endif
#endif

// ============================================================================
// KEM (Key Encapsulation Mechanism)
#if OPENSSL_VERSION_MAJOR >= 3

class KEM final {
 public:
  struct EncapsulateResult {
    DataPointer ciphertext;
    DataPointer shared_key;

    EncapsulateResult() = default;
    EncapsulateResult(DataPointer ct, DataPointer sk) : ciphertext(std::move(ct)), shared_key(std::move(sk)) {}
  };

  // Encapsulate a shared secret using KEM with a public key.
  // Returns both the ciphertext and shared secret.
  static std::optional<EncapsulateResult> Encapsulate(const EVPKeyPointer& public_key);

  // Decapsulate a shared secret using KEM with a private key and ciphertext.
  // Returns the shared secret.
  static DataPointer Decapsulate(const EVPKeyPointer& private_key, const Buffer<const void>& ciphertext);

 private:
#if !OPENSSL_VERSION_PREREQ(3, 5)
  static bool SetOperationParameter(EVP_PKEY_CTX* ctx, const EVPKeyPointer& key);
#endif
};

#endif // OPENSSL_VERSION_MAJOR >= 3

#include "ncrypto/version.h"

} // namespace ncrypto
