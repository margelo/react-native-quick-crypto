#include "ncrypto.h"
#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#ifndef NCRYPTO_NO_KDF_H
#include <openssl/kdf.h>
#endif
#ifdef OPENSSL_IS_BORINGSSL
#include <openssl/hkdf.h>
#endif

#include <algorithm>
#include <array>
#include <climits>
#include <cstring>
#include <string_view>
#include <vector>
#if OPENSSL_VERSION_MAJOR >= 3
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#if OPENSSL_VERSION_NUMBER >= 0x30200000L
#include <openssl/thread.h>
#endif
#endif
#if OPENSSL_WITH_PQC
struct PQCMapping {
  const char* name;
  int nid;
};

constexpr static PQCMapping pqc_mappings[] = {
    {"ML-DSA-44", EVP_PKEY_ML_DSA_44},
    {"ML-DSA-65", EVP_PKEY_ML_DSA_65},
    {"ML-DSA-87", EVP_PKEY_ML_DSA_87},
    {"ML-KEM-512", EVP_PKEY_ML_KEM_512},
    {"ML-KEM-768", EVP_PKEY_ML_KEM_768},
    {"ML-KEM-1024", EVP_PKEY_ML_KEM_1024},
    {"SLH-DSA-SHA2-128f", EVP_PKEY_SLH_DSA_SHA2_128F},
    {"SLH-DSA-SHA2-128s", EVP_PKEY_SLH_DSA_SHA2_128S},
    {"SLH-DSA-SHA2-192f", EVP_PKEY_SLH_DSA_SHA2_192F},
    {"SLH-DSA-SHA2-192s", EVP_PKEY_SLH_DSA_SHA2_192S},
    {"SLH-DSA-SHA2-256f", EVP_PKEY_SLH_DSA_SHA2_256F},
    {"SLH-DSA-SHA2-256s", EVP_PKEY_SLH_DSA_SHA2_256S},
    {"SLH-DSA-SHAKE-128f", EVP_PKEY_SLH_DSA_SHAKE_128F},
    {"SLH-DSA-SHAKE-128s", EVP_PKEY_SLH_DSA_SHAKE_128S},
    {"SLH-DSA-SHAKE-192f", EVP_PKEY_SLH_DSA_SHAKE_192F},
    {"SLH-DSA-SHAKE-192s", EVP_PKEY_SLH_DSA_SHAKE_192S},
    {"SLH-DSA-SHAKE-256f", EVP_PKEY_SLH_DSA_SHAKE_256F},
    {"SLH-DSA-SHAKE-256s", EVP_PKEY_SLH_DSA_SHAKE_256S},
};

#endif

// EVP_PKEY_CTX_set_dsa_paramgen_q_bits was added in OpenSSL 1.1.1e.
#if OPENSSL_VERSION_NUMBER < 0x1010105fL
#define EVP_PKEY_CTX_set_dsa_paramgen_q_bits(ctx, qbits)                                                                                   \
  EVP_PKEY_CTX_ctrl((ctx), EVP_PKEY_DSA, EVP_PKEY_OP_PARAMGEN, EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS, (qbits), nullptr)
#endif

namespace ncrypto {
namespace {
  using BignumCtxPointer = DeleteFnPtr<BN_CTX, BN_CTX_free>;
  using BignumGenCallbackPointer = DeleteFnPtr<BN_GENCB, BN_GENCB_free>;
  using NetscapeSPKIPointer = DeleteFnPtr<NETSCAPE_SPKI, NETSCAPE_SPKI_free>;

  static constexpr int kX509NameFlagsRFC2253WithinUtf8JSON = XN_FLAG_RFC2253 & ~ASN1_STRFLGS_ESC_MSB & ~ASN1_STRFLGS_ESC_CTRL;
} // namespace

// ============================================================================

ClearErrorOnReturn::ClearErrorOnReturn(CryptoErrorList* errors) : errors_(errors) {
  ERR_clear_error();
}

ClearErrorOnReturn::~ClearErrorOnReturn() {
  if (errors_ != nullptr)
    errors_->capture();
  ERR_clear_error();
}

int ClearErrorOnReturn::peekError() {
  return ERR_peek_error();
}

MarkPopErrorOnReturn::MarkPopErrorOnReturn(CryptoErrorList* errors) : errors_(errors) {
  ERR_set_mark();
}

MarkPopErrorOnReturn::~MarkPopErrorOnReturn() {
  if (errors_ != nullptr)
    errors_->capture();
  ERR_pop_to_mark();
}

int MarkPopErrorOnReturn::peekError() {
  return ERR_peek_error();
}

CryptoErrorList::CryptoErrorList(CryptoErrorList::Option option) {
  if (option == Option::CAPTURE_ON_CONSTRUCT)
    capture();
}

void CryptoErrorList::capture() {
  errors_.clear();
  while (const auto err = ERR_get_error()) {
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    errors_.emplace_front(buf);
  }
}

void CryptoErrorList::add(std::string error) {
  errors_.push_back(error);
}

std::optional<std::string> CryptoErrorList::pop_back() {
  if (errors_.empty())
    return std::nullopt;
  std::string error = errors_.back();
  errors_.pop_back();
  return error;
}

std::optional<std::string> CryptoErrorList::pop_front() {
  if (errors_.empty())
    return std::nullopt;
  std::string error = errors_.front();
  errors_.pop_front();
  return error;
}

// ============================================================================
DataPointer DataPointer::Alloc(size_t len) {
#ifdef OPENSSL_IS_BORINGSSL
  // Boringssl does not implement OPENSSL_zalloc
  auto ptr = OPENSSL_malloc(len);
  if (ptr == nullptr)
    return {};
  memset(ptr, 0, len);
  return DataPointer(ptr, len);
#else
  return DataPointer(OPENSSL_zalloc(len), len);
#endif
}

DataPointer DataPointer::SecureAlloc(size_t len) {
#ifndef OPENSSL_IS_BORINGSSL
  auto ptr = OPENSSL_secure_zalloc(len);
  if (ptr == nullptr)
    return {};
  return DataPointer(ptr, len, true);
#else
  // BoringSSL does not implement the OPENSSL_secure_zalloc API.
  auto ptr = OPENSSL_malloc(len);
  if (ptr == nullptr)
    return {};
  memset(ptr, 0, len);
  return DataPointer(ptr, len);
#endif
}

size_t DataPointer::GetSecureHeapUsed() {
#ifndef OPENSSL_IS_BORINGSSL
  return CRYPTO_secure_malloc_initialized() ? CRYPTO_secure_used() : 0;
#else
  // BoringSSL does not have the secure heap and therefore
  // will always return 0.
  return 0;
#endif
}

DataPointer::InitSecureHeapResult DataPointer::TryInitSecureHeap(size_t amount, size_t min) {
#ifndef OPENSSL_IS_BORINGSSL
  switch (CRYPTO_secure_malloc_init(amount, min)) {
    case 0:
      return InitSecureHeapResult::FAILED;
    case 2:
      return InitSecureHeapResult::UNABLE_TO_MEMORY_MAP;
    case 1:
      return InitSecureHeapResult::OK;
    default:
      return InitSecureHeapResult::FAILED;
  }
#else
  // BoringSSL does not actually support the secure heap
  return InitSecureHeapResult::FAILED;
#endif
}

DataPointer DataPointer::Copy(const Buffer<const void>& buffer) {
  return DataPointer(OPENSSL_memdup(buffer.data, buffer.len), buffer.len);
}

DataPointer::DataPointer(void* data, size_t length, bool secure) : data_(data), len_(length), secure_(secure) {}

DataPointer::DataPointer(const Buffer<void>& buffer, bool secure) : data_(buffer.data), len_(buffer.len), secure_(secure) {}

DataPointer::DataPointer(DataPointer&& other) noexcept : data_(other.data_), len_(other.len_), secure_(other.secure_) {
  other.data_ = nullptr;
  other.len_ = 0;
  other.secure_ = false;
}

DataPointer& DataPointer::operator=(DataPointer&& other) noexcept {
  if (this == &other)
    return *this;
  this->~DataPointer();
  return *new (this) DataPointer(std::move(other));
}

DataPointer::~DataPointer() {
  reset();
}

void DataPointer::zero() {
  if (!data_)
    return;
  OPENSSL_cleanse(data_, len_);
}

void DataPointer::free() {
  if (data_ != nullptr) {
    if (secure_) {
      OPENSSL_secure_clear_free(data_, len_);
    } else {
      OPENSSL_clear_free(data_, len_);
    }
  }
}

void DataPointer::reset(void* data, size_t length) {
  free();
  data_ = data;
  len_ = length;
}

void DataPointer::reset(const Buffer<void>& buffer) {
  reset(buffer.data, buffer.len);
}

Buffer<void> DataPointer::release() {
  Buffer<void> buf{
      .data = data_,
      .len = len_,
  };
  data_ = nullptr;
  len_ = 0;
  return buf;
}

DataPointer DataPointer::resize(size_t len) {
  size_t actual_len = std::min(len_, len);
  auto buf = release();
  if (actual_len == len_)
    return DataPointer(buf.data, actual_len);
  auto new_data = OPENSSL_realloc(buf.data, actual_len);
  if (new_data == nullptr) {
    free();
    return {};
  }
  buf.data = new_data;
  buf.len = actual_len;
  return DataPointer(buf);
}

// ============================================================================
bool isFipsEnabled() {
  ClearErrorOnReturn clear_error_on_return;
#if OPENSSL_VERSION_MAJOR >= 3
  return EVP_default_properties_is_fips_enabled(nullptr) == 1;
#else
  return FIPS_mode() == 1;
#endif
}

bool setFipsEnabled(bool enable, CryptoErrorList* errors) {
  if (isFipsEnabled() == enable)
    return true;
  ClearErrorOnReturn clearErrorOnReturn(errors);
#if OPENSSL_VERSION_MAJOR >= 3
  return EVP_default_properties_enable_fips(nullptr, enable ? 1 : 0) == 1 && EVP_default_properties_is_fips_enabled(nullptr);
#else
  return FIPS_mode_set(enable ? 1 : 0) == 1;
#endif
}

bool testFipsEnabled() {
  ClearErrorOnReturn clear_error_on_return;
#if OPENSSL_VERSION_MAJOR >= 3
  OSSL_PROVIDER* fips_provider = nullptr;
  if (OSSL_PROVIDER_available(nullptr, "fips")) {
    fips_provider = OSSL_PROVIDER_load(nullptr, "fips");
  }
  if (fips_provider == nullptr)
    return false;
  int result = OSSL_PROVIDER_self_test(fips_provider);
  OSSL_PROVIDER_unload(fips_provider);
  return result;
#else
#ifdef OPENSSL_FIPS
  return FIPS_selftest();
#else  // OPENSSL_FIPS
  return false;
#endif // OPENSSL_FIPS
#endif
}

// ============================================================================
// Bignum
BignumPointer::BignumPointer(BIGNUM* bignum) : bn_(bignum) {}

BignumPointer::BignumPointer(const unsigned char* data, size_t len) : BignumPointer(BN_bin2bn(data, len, nullptr)) {}

BignumPointer::BignumPointer(BignumPointer&& other) noexcept : bn_(other.release()) {}

BignumPointer BignumPointer::New() {
  return BignumPointer(BN_new());
}

BignumPointer BignumPointer::NewSecure() {
#ifdef OPENSSL_IS_BORINGSSL
  // Boringssl does not implement BN_secure_new.
  return New();
#else
  return BignumPointer(BN_secure_new());
#endif
}

BignumPointer& BignumPointer::operator=(BignumPointer&& other) noexcept {
  if (this == &other)
    return *this;
  this->~BignumPointer();
  return *new (this) BignumPointer(std::move(other));
}

BignumPointer::~BignumPointer() {
  reset();
}

void BignumPointer::reset(BIGNUM* bn) {
  bn_.reset(bn);
}

void BignumPointer::reset(const unsigned char* data, size_t len) {
  reset(BN_bin2bn(data, len, nullptr));
}

BIGNUM* BignumPointer::release() {
  return bn_.release();
}

size_t BignumPointer::byteLength() const {
  if (bn_ == nullptr)
    return 0;
  return BN_num_bytes(bn_.get());
}

size_t BignumPointer::bitLength() const {
  if (bn_ == nullptr)
    return 0;
  return BN_num_bits(bn_.get());
}

DataPointer BignumPointer::encode() const {
  return EncodePadded(bn_.get(), byteLength());
}

DataPointer BignumPointer::encodePadded(size_t size) const {
  return EncodePadded(bn_.get(), size);
}

size_t BignumPointer::encodeInto(unsigned char* out) const {
  if (!bn_)
    return 0;
  return BN_bn2bin(bn_.get(), out);
}

size_t BignumPointer::encodePaddedInto(unsigned char* out, size_t size) const {
  if (!bn_)
    return 0;
  return BN_bn2binpad(bn_.get(), out, size);
}

DataPointer BignumPointer::Encode(const BIGNUM* bn) {
  return EncodePadded(bn, bn != nullptr ? BN_num_bytes(bn) : 0);
}

bool BignumPointer::setWord(unsigned long w) { // NOLINT(runtime/int)
  if (!bn_)
    return false;
  return BN_set_word(bn_.get(), w) == 1;
}

unsigned long BignumPointer::GetWord(const BIGNUM* bn) { // NOLINT(runtime/int)
  return BN_get_word(bn);
}

unsigned long BignumPointer::getWord() const { // NOLINT(runtime/int)
  if (!bn_)
    return 0;
  return GetWord(bn_.get());
}

DataPointer BignumPointer::EncodePadded(const BIGNUM* bn, size_t s) {
  if (bn == nullptr)
    return DataPointer();
  size_t size = std::max(s, static_cast<size_t>(GetByteCount(bn)));
  auto buf = DataPointer::Alloc(size);
  BN_bn2binpad(bn, reinterpret_cast<unsigned char*>(buf.get()), size);
  return buf;
}
size_t BignumPointer::EncodePaddedInto(const BIGNUM* bn, unsigned char* out, size_t size) {
  if (bn == nullptr)
    return 0;
  return BN_bn2binpad(bn, out, size);
}

int BignumPointer::operator<=>(const BignumPointer& other) const noexcept {
  if (bn_ == nullptr && other.bn_ != nullptr)
    return -1;
  if (bn_ != nullptr && other.bn_ == nullptr)
    return 1;
  if (bn_ == nullptr && other.bn_ == nullptr)
    return 0;
  return BN_cmp(bn_.get(), other.bn_.get());
}

int BignumPointer::operator<=>(const BIGNUM* other) const noexcept {
  if (bn_ == nullptr && other != nullptr)
    return -1;
  if (bn_ != nullptr && other == nullptr)
    return 1;
  if (bn_ == nullptr && other == nullptr)
    return 0;
  return BN_cmp(bn_.get(), other);
}

DataPointer BignumPointer::toHex() const {
  if (!bn_)
    return {};
  char* hex = BN_bn2hex(bn_.get());
  if (!hex)
    return {};
  return DataPointer(hex, strlen(hex));
}

int BignumPointer::GetBitCount(const BIGNUM* bn) {
  return BN_num_bits(bn);
}

int BignumPointer::GetByteCount(const BIGNUM* bn) {
  return BN_num_bytes(bn);
}

bool BignumPointer::isZero() const {
  return bn_ && BN_is_zero(bn_.get());
}

bool BignumPointer::isOne() const {
  return bn_ && BN_is_one(bn_.get());
}

const BIGNUM* BignumPointer::One() {
  return BN_value_one();
}

BignumPointer BignumPointer::clone() {
  if (!bn_)
    return {};
  return BignumPointer(BN_dup(bn_.get()));
}

int BignumPointer::isPrime(int nchecks, BignumPointer::PrimeCheckCallback innerCb) const {
  BignumCtxPointer ctx(BN_CTX_new());
  BignumGenCallbackPointer cb(nullptr);
  if (innerCb != nullptr) {
    cb = BignumGenCallbackPointer(BN_GENCB_new());
    if (!cb) [[unlikely]]
      return -1;
    BN_GENCB_set(
        cb.get(),
        // TODO(@jasnell): This could be refactored to allow inlining.
        // Not too important right now tho.
        [](int a, int b, BN_GENCB* ctx) mutable -> int {
          // BN_GENCB is opaque in OpenSSL 3.x, must use accessor
          PrimeCheckCallback& ptr = *static_cast<PrimeCheckCallback*>(BN_GENCB_get_arg(ctx));
          return ptr(a, b) ? 1 : 0;
        },
        &innerCb);
  }
  const int minimum_checks = bitLength() > 2048 ? 128 : 64;
  const int repetitions = nchecks > minimum_checks ? 1 + (nchecks - 1) / minimum_checks : 1;
  for (int i = 0; i < repetitions; i++) {
    const int result = BN_check_prime(get(), ctx.get(), cb.get());
    if (result != 1)
      return result;
  }
  return 1;
}

BignumPointer BignumPointer::NewPrime(const PrimeConfig& params, PrimeCheckCallback cb) {
  BignumPointer prime(BN_new());
  if (!prime || !prime.generate(params, std::move(cb))) {
    return {};
  }
  return prime;
}

bool BignumPointer::generate(const PrimeConfig& params, PrimeCheckCallback innerCb) const {
  // BN_generate_prime_ex() calls RAND_bytes_ex() internally.
  // Make sure the CSPRNG is properly seeded.
  std::ignore = CSPRNG(nullptr, 0);
  BignumGenCallbackPointer cb(nullptr);
  if (innerCb != nullptr) {
    cb = BignumGenCallbackPointer(BN_GENCB_new());
    if (!cb) [[unlikely]]
      return -1;
    BN_GENCB_set(
        cb.get(),
        [](int a, int b, BN_GENCB* ctx) mutable -> int {
          // BN_GENCB is opaque in OpenSSL 3.x, must use accessor
          PrimeCheckCallback& ptr = *static_cast<PrimeCheckCallback*>(BN_GENCB_get_arg(ctx));
          return ptr(a, b) ? 1 : 0;
        },
        &innerCb);
  }
  if (BN_generate_prime_ex(get(), params.bits, params.safe ? 1 : 0, params.add.get(), params.rem.get(), cb.get()) == 0) {
    return false;
  }

  return true;
}

BignumPointer BignumPointer::NewSub(const BignumPointer& a, const BignumPointer& b) {
  BignumPointer res = New();
  if (!res)
    return {};
  if (!BN_sub(res.get(), a.get(), b.get())) {
    return {};
  }
  return res;
}

BignumPointer BignumPointer::NewLShift(size_t length) {
  BignumPointer res = New();
  if (!res)
    return {};
  if (!BN_lshift(res.get(), One(), length)) {
    return {};
  }
  return res;
}

// ============================================================================
// Utility methods

bool CSPRNG(void* buffer, size_t length) {
  auto buf = reinterpret_cast<unsigned char*>(buffer);
  do {
    if (1 == RAND_status()) {
#if OPENSSL_VERSION_MAJOR >= 3
      if (1 == RAND_bytes_ex(nullptr, buf, length, 0)) {
        return true;
      }
#else
      while (length > INT_MAX && 1 == RAND_bytes(buf, INT_MAX)) {
        buf += INT_MAX;
        length -= INT_MAX;
      }
      if (length <= INT_MAX && 1 == RAND_bytes(buf, static_cast<int>(length)))
        return true;
#endif
    }
#if OPENSSL_VERSION_MAJOR >= 3
    const auto code = ERR_peek_last_error();
    // A misconfigured OpenSSL 3 installation may report 1 from RAND_poll()
    // and RAND_status() but fail in RAND_bytes() if it cannot look up
    // a matching algorithm for the CSPRNG.
    if (ERR_GET_LIB(code) == ERR_LIB_RAND) {
      const auto reason = ERR_GET_REASON(code);
      if (reason == RAND_R_ERROR_INSTANTIATING_DRBG || reason == RAND_R_UNABLE_TO_FETCH_DRBG || reason == RAND_R_UNABLE_TO_CREATE_DRBG) {
        return false;
      }
    }
#endif
  } while (1 == RAND_poll());

  return false;
}

int NoPasswordCallback(char*, int, int, void*) {
  return 0;
}

int PasswordCallback(char* buf, int size, int, void* u) {
  auto passphrase = static_cast<const Buffer<char>*>(u);
  if (passphrase != nullptr) {
    size_t buflen = static_cast<size_t>(size);
    size_t len = passphrase->len;
    if (buflen < len)
      return -1;
    memcpy(buf, reinterpret_cast<const char*>(passphrase->data), len);
    return len;
  }

  return -1;
}

// Algorithm: http://howardhinnant.github.io/date_algorithms.html
constexpr int days_from_epoch(int y, unsigned m, unsigned d) {
  y -= m <= 2;
  const int era = (y >= 0 ? y : y - 399) / 400;
  const unsigned yoe = static_cast<unsigned>(y - era * 400);           // [0, 399]
  const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1; // [0, 365]
  const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;          // [0, 146096]
  return era * 146097 + static_cast<int>(doe) - 719468;
}

#ifndef OPENSSL_IS_BORINGSSL
// tm must be in UTC
// using time_t causes problems on 32-bit systems and windows x64.
int64_t PortableTimeGM(struct tm* t) {
  int year = t->tm_year + 1900;
  int month = t->tm_mon;
  if (month > 11) {
    year += month / 12;
    month %= 12;
  } else if (month < 0) {
    int years_diff = (11 - month) / 12;
    year -= years_diff;
    month += 12 * years_diff;
  }
  int days_since_epoch = days_from_epoch(year, month + 1, t->tm_mday);

  return 60 * (60 * (24LL * static_cast<int64_t>(days_since_epoch) + t->tm_hour) + t->tm_min) + t->tm_sec;
}
#endif

// ============================================================================
// SPKAC

bool VerifySpkac(const char* input, size_t length) {
#ifdef OPENSSL_IS_BORINGSSL
  // OpenSSL uses EVP_DecodeBlock, which explicitly removes trailing characters,
  // while BoringSSL uses EVP_DecodedLength and EVP_DecodeBase64, which do not.
  // As such, we trim those characters here for compatibility.
  //
  // find_last_not_of can return npos, which is the maximum value of size_t.
  // The + 1 will force a roll-ver to 0, which is the correct value. in that
  // case.
  length = std::string_view(input, length).find_last_not_of(" \n\r\t") + 1;
#endif
  NetscapeSPKIPointer spki(NETSCAPE_SPKI_b64_decode(input, length));
  if (!spki)
    return false;

  EVPKeyPointer pkey(X509_PUBKEY_get(spki->spkac->pubkey));
  return pkey ? NETSCAPE_SPKI_verify(spki.get(), pkey.get()) > 0 : false;
}

BIOPointer ExportPublicKey(const char* input, size_t length) {
  BIOPointer bio(BIO_new(BIO_s_mem()));
  if (!bio)
    return {};

#ifdef OPENSSL_IS_BORINGSSL
  // OpenSSL uses EVP_DecodeBlock, which explicitly removes trailing characters,
  // while BoringSSL uses EVP_DecodedLength and EVP_DecodeBase64, which do not.
  // As such, we trim those characters here for compatibility.
  length = std::string_view(input, length).find_last_not_of(" \n\r\t") + 1;
#endif
  NetscapeSPKIPointer spki(NETSCAPE_SPKI_b64_decode(input, length));
  if (!spki)
    return {};

  EVPKeyPointer pkey(NETSCAPE_SPKI_get_pubkey(spki.get()));
  if (!pkey)
    return {};

  if (PEM_write_bio_PUBKEY(bio.get(), pkey.get()) <= 0)
    return {};

  return bio;
}

Buffer<char> ExportChallenge(const char* input, size_t length) {
#ifdef OPENSSL_IS_BORINGSSL
  // OpenSSL uses EVP_DecodeBlock, which explicitly removes trailing characters,
  // while BoringSSL uses EVP_DecodedLength and EVP_DecodeBase64, which do not.
  // As such, we trim those characters here for compatibility.
  length = std::string_view(input, length).find_last_not_of(" \n\r\t") + 1;
#endif
  NetscapeSPKIPointer sp(NETSCAPE_SPKI_b64_decode(input, length));
  if (!sp)
    return {};

  unsigned char* buf = nullptr;
  int buf_size = ASN1_STRING_to_UTF8(&buf, sp->spkac->challenge);
  if (buf_size >= 0) {
    return {
        .data = reinterpret_cast<char*>(buf),
        .len = static_cast<size_t>(buf_size),
    };
  }

  return {};
}

bool VerifySpkac(const Buffer<const char>& input) {
  return VerifySpkac(input.data, input.len);
}

BIOPointer ExportPublicKey(const Buffer<const char>& input) {
  return ExportPublicKey(input.data, input.len);
}

DataPointer ExportChallenge(const Buffer<const char>& input) {
  auto buf = ExportChallenge(input.data, input.len);
  if (buf.data != nullptr) {
    return DataPointer(buf.data, buf.len);
  }
  return {};
}

// ============================================================================
namespace {
  enum class AltNameOption {
    NONE,
    UTF8,
  };

  bool IsSafeAltName(const char* name, size_t length, AltNameOption option) {
    for (size_t i = 0; i < length; i++) {
      char c = name[i];
      switch (c) {
        case '"':
        case '\\':
          // These mess with encoding rules.
          // Fall through.
        case ',':
          // Commas make it impossible to split the list of subject alternative
          // names unambiguously, which is why we have to escape.
          // Fall through.
        case '\'':
          // Single quotes are unlikely to appear in any legitimate values, but
          // they could be used to make a value look like it was escaped (i.e.,
          // enclosed in single/double quotes).
          return false;
        default:
          if (option == AltNameOption::UTF8) {
            // In UTF8 strings, we require escaping for any ASCII control
            // character, but NOT for non-ASCII characters. Note that all bytes of
            // any code point that consists of more than a single byte have their
            // MSB set.
            if (static_cast<unsigned char>(c) < ' ' || c == '\x7f') {
              return false;
            }
          } else {
            // Check if the char is a control character or non-ASCII character.
            // Note that char may or may not be a signed type. Regardless,
            // non-ASCII values will always be outside of this range.
            if (c < ' ' || c > '~') {
              return false;
            }
          }
      }
    }
    return true;
  }

  void PrintAltName(const BIOPointer& out, const char* name, size_t length, AltNameOption option = AltNameOption::NONE,
                    const char* safe_prefix = nullptr) {
    if (IsSafeAltName(name, length, option)) {
      // For backward-compatibility, append "safe" names without any
      // modifications.
      if (safe_prefix != nullptr) {
        BIO_printf(out.get(), "%s:", safe_prefix);
      }
      BIO_write(out.get(), name, length);
    } else {
      // If a name is not "safe", we cannot embed it without special
      // encoding. This does not usually happen, but we don't want to hide
      // it from the user either. We use JSON compatible escaping here.
      BIO_write(out.get(), "\"", 1);
      if (safe_prefix != nullptr) {
        BIO_printf(out.get(), "%s:", safe_prefix);
      }
      for (size_t j = 0; j < length; j++) {
        char c = static_cast<char>(name[j]);
        if (c == '\\') {
          BIO_write(out.get(), "\\\\", 2);
        } else if (c == '"') {
          BIO_write(out.get(), "\\\"", 2);
        } else if ((c >= ' ' && c != ',' && c <= '~') || (option == AltNameOption::UTF8 && (c & 0x80))) {
          // Note that the above condition explicitly excludes commas, which means
          // that those are encoded as Unicode escape sequences in the "else"
          // block. That is not strictly necessary, and Node.js itself would parse
          // it correctly either way. We only do this to account for third-party
          // code that might be splitting the string at commas (as Node.js itself
          // used to do).
          BIO_write(out.get(), &c, 1);
        } else {
          // Control character or non-ASCII character. We treat everything as
          // Latin-1, which corresponds to the first 255 Unicode code points.
          const char hex[] = "0123456789abcdef";
          char u[] = {'\\', 'u', '0', '0', hex[(c & 0xf0) >> 4], hex[c & 0x0f]};
          BIO_write(out.get(), u, sizeof(u));
        }
      }
      BIO_write(out.get(), "\"", 1);
    }
  }

  // This function emulates the behavior of i2v_GENERAL_NAME in a safer and less
  // ambiguous way. "othername:" entries use the GENERAL_NAME_print format.
  bool PrintGeneralName(const BIOPointer& out, const GENERAL_NAME* gen) {
    if (gen->type == GEN_DNS) {
      ASN1_IA5STRING* name = gen->d.dNSName;
      BIO_write(out.get(), "DNS:", 4);
      // Note that the preferred name syntax (see RFCs 5280 and 1034) with
      // wildcards is a subset of what we consider "safe", so spec-compliant DNS
      // names will never need to be escaped.
      PrintAltName(out, reinterpret_cast<const char*>(ASN1_STRING_get0_data(name)), ASN1_STRING_length(name));
    } else if (gen->type == GEN_EMAIL) {
      ASN1_IA5STRING* name = gen->d.rfc822Name;
      BIO_write(out.get(), "email:", 6);
      PrintAltName(out, reinterpret_cast<const char*>(ASN1_STRING_get0_data(name)), ASN1_STRING_length(name));
    } else if (gen->type == GEN_URI) {
      ASN1_IA5STRING* name = gen->d.uniformResourceIdentifier;
      BIO_write(out.get(), "URI:", 4);
      // The set of "safe" names was designed to include just about any URI,
      // with a few exceptions, most notably URIs that contains commas (see
      // RFC 2396). In other words, most legitimate URIs will not require
      // escaping.
      PrintAltName(out, reinterpret_cast<const char*>(ASN1_STRING_get0_data(name)), ASN1_STRING_length(name));
    } else if (gen->type == GEN_DIRNAME) {
      // Earlier versions of Node.js used X509_NAME_oneline to print the X509_NAME
      // object. The format was non standard and should be avoided. The use of
      // X509_NAME_oneline is discouraged by OpenSSL but was required for backward
      // compatibility. Conveniently, X509_NAME_oneline produced ASCII and the
      // output was unlikely to contains commas or other characters that would
      // require escaping. However, it SHOULD NOT produce ASCII output since an
      // RFC5280 AttributeValue may be a UTF8String.
      // Newer versions of Node.js have since switched to X509_NAME_print_ex to
      // produce a better format at the cost of backward compatibility. The new
      // format may contain Unicode characters and it is likely to contain commas,
      // which require escaping. Fortunately, the recently safeguarded function
      // PrintAltName handles all of that safely.
      BIO_printf(out.get(), "DirName:");
      BIOPointer tmp(BIO_new(BIO_s_mem()));
      NCRYPTO_ASSERT_TRUE(tmp);
      if (X509_NAME_print_ex(tmp.get(), gen->d.dirn, 0, kX509NameFlagsRFC2253WithinUtf8JSON) < 0) {
        return false;
      }
      char* oline = nullptr;
      long n_bytes = BIO_get_mem_data(tmp.get(), &oline); // NOLINT(runtime/int)
      NCRYPTO_ASSERT_TRUE(n_bytes >= 0);
      PrintAltName(out, oline, static_cast<size_t>(n_bytes), ncrypto::AltNameOption::UTF8, nullptr);
    } else if (gen->type == GEN_IPADD) {
      BIO_printf(out.get(), "IP Address:");
      const ASN1_OCTET_STRING* ip = gen->d.ip;
      const unsigned char* b = ASN1_STRING_get0_data(ip);
      int ip_len = ASN1_STRING_length(ip);
      if (ip_len == 4) {
        BIO_printf(out.get(), "%d.%d.%d.%d", b[0], b[1], b[2], b[3]);
      } else if (ip_len == 16) {
        for (unsigned int j = 0; j < 8; j++) {
          uint16_t pair = (b[2 * j] << 8) | b[2 * j + 1];
          BIO_printf(out.get(), (j == 0) ? "%X" : ":%X", pair);
        }
      } else {
#if OPENSSL_VERSION_MAJOR >= 3
        BIO_printf(out.get(), "<invalid length=%d>", ip_len);
#else
        BIO_printf(out.get(), "<invalid>");
#endif
      }
    } else if (gen->type == GEN_RID) {
      // Unlike OpenSSL's default implementation, never print the OID as text and
      // instead always print its numeric representation.
      char oline[256];
      OBJ_obj2txt(oline, sizeof(oline), gen->d.rid, true);
      BIO_printf(out.get(), "Registered ID:%s", oline);
    } else if (gen->type == GEN_OTHERNAME) {
      // The format that is used here is based on OpenSSL's implementation of
      // GENERAL_NAME_print (as of OpenSSL 3.0.1). Earlier versions of Node.js
      // instead produced the same format as i2v_GENERAL_NAME, which was somewhat
      // awkward, especially when passed to translatePeerCertificate.
      bool unicode = true;
      const char* prefix = nullptr;
      // OpenSSL 1.1.1 does not support othername in GENERAL_NAME_print and may
      // not define these NIDs.
#if OPENSSL_VERSION_MAJOR >= 3
      int nid = OBJ_obj2nid(gen->d.otherName->type_id);
      switch (nid) {
        case NID_id_on_SmtpUTF8Mailbox:
          prefix = "SmtpUTF8Mailbox";
          break;
        case NID_XmppAddr:
          prefix = "XmppAddr";
          break;
        case NID_SRVName:
          prefix = "SRVName";
          unicode = false;
          break;
        case NID_ms_upn:
          prefix = "UPN";
          break;
        case NID_NAIRealm:
          prefix = "NAIRealm";
          break;
      }
#endif // OPENSSL_VERSION_MAJOR >= 3
      int val_type = gen->d.otherName->value->type;
      if (prefix == nullptr || (unicode && val_type != V_ASN1_UTF8STRING) || (!unicode && val_type != V_ASN1_IA5STRING)) {
        BIO_printf(out.get(), "othername:<unsupported>");
      } else {
        BIO_printf(out.get(), "othername:");
        if (unicode) {
          auto name = gen->d.otherName->value->value.utf8string;
          PrintAltName(out, reinterpret_cast<const char*>(ASN1_STRING_get0_data(name)), ASN1_STRING_length(name), AltNameOption::UTF8,
                       prefix);
        } else {
          auto name = gen->d.otherName->value->value.ia5string;
          PrintAltName(out, reinterpret_cast<const char*>(ASN1_STRING_get0_data(name)), ASN1_STRING_length(name), AltNameOption::NONE,
                       prefix);
        }
      }
    } else if (gen->type == GEN_X400) {
      // TODO(tniessen): this is what OpenSSL does, implement properly instead
      BIO_printf(out.get(), "X400Name:<unsupported>");
    } else if (gen->type == GEN_EDIPARTY) {
      // TODO(tniessen): this is what OpenSSL does, implement properly instead
      BIO_printf(out.get(), "EdiPartyName:<unsupported>");
    } else {
      // This is safe because X509V3_EXT_d2i would have returned nullptr in this
      // case already.
      unreachable();
    }

    return true;
  }
} // namespace

bool SafeX509SubjectAltNamePrint(const BIOPointer& out, const X509_EXTENSION* ext) {
  // const_cast needed for OpenSSL < 4.0 which lacks const-correctness
  auto* mext = const_cast<X509_EXTENSION*>(ext);
  auto ret = OBJ_obj2nid(X509_EXTENSION_get_object(mext));
  if (ret != NID_subject_alt_name)
    return false;

  GENERAL_NAMES* names = static_cast<GENERAL_NAMES*>(X509V3_EXT_d2i(mext));
  if (names == nullptr)
    return false;

  bool ok = true;

  for (OPENSSL_SIZE_T i = 0; i < sk_GENERAL_NAME_num(names); i++) {
    GENERAL_NAME* gen = sk_GENERAL_NAME_value(names, i);

    if (i != 0)
      BIO_write(out.get(), ", ", 2);

    if (!(ok = ncrypto::PrintGeneralName(out, gen))) {
      break;
    }
  }
  sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);

  return ok;
}

bool SafeX509InfoAccessPrint(const BIOPointer& out, const X509_EXTENSION* ext) {
  // const_cast needed for OpenSSL < 4.0 which lacks const-correctness
  auto* mext = const_cast<X509_EXTENSION*>(ext);
  auto ret = OBJ_obj2nid(X509_EXTENSION_get_object(mext));
  if (ret != NID_info_access)
    return false;

  AUTHORITY_INFO_ACCESS* descs = static_cast<AUTHORITY_INFO_ACCESS*>(X509V3_EXT_d2i(mext));
  if (descs == nullptr)
    return false;

  bool ok = true;

  for (OPENSSL_SIZE_T i = 0; i < sk_ACCESS_DESCRIPTION_num(descs); i++) {
    ACCESS_DESCRIPTION* desc = sk_ACCESS_DESCRIPTION_value(descs, i);

    if (i != 0)
      BIO_write(out.get(), "\n", 1);

    char objtmp[80];
    i2t_ASN1_OBJECT(objtmp, sizeof(objtmp), desc->method);
    BIO_printf(out.get(), "%s - ", objtmp);
    if (!(ok = ncrypto::PrintGeneralName(out, desc->location))) {
      break;
    }
  }
  sk_ACCESS_DESCRIPTION_pop_free(descs, ACCESS_DESCRIPTION_free);

#if OPENSSL_VERSION_MAJOR < 3
  BIO_write(out.get(), "\n", 1);
#endif

  return ok;
}

// ============================================================================
// X509Pointer

X509Pointer::X509Pointer(X509* x509) : cert_(x509) {}

X509Pointer::X509Pointer(X509Pointer&& other) noexcept : cert_(other.release()) {}

X509Pointer& X509Pointer::operator=(X509Pointer&& other) noexcept {
  if (this == &other)
    return *this;
  this->~X509Pointer();
  return *new (this) X509Pointer(std::move(other));
}

X509Pointer::~X509Pointer() {
  reset();
}

void X509Pointer::reset(X509* x509) {
  cert_.reset(x509);
}

X509* X509Pointer::release() {
  return cert_.release();
}

X509View X509Pointer::view() const {
  return X509View(cert_.get());
}

BIOPointer X509View::toPEM() const {
  ClearErrorOnReturn clearErrorOnReturn;
  if (cert_ == nullptr)
    return {};
  BIOPointer bio(BIO_new(BIO_s_mem()));
  if (!bio)
    return {};
  if (PEM_write_bio_X509(bio.get(), const_cast<X509*>(cert_)) <= 0)
    return {};
  return bio;
}

BIOPointer X509View::toDER() const {
  ClearErrorOnReturn clearErrorOnReturn;
  if (cert_ == nullptr)
    return {};
  BIOPointer bio(BIO_new(BIO_s_mem()));
  if (!bio)
    return {};
  if (i2d_X509_bio(bio.get(), const_cast<X509*>(cert_)) <= 0)
    return {};
  return bio;
}

BIOPointer X509View::getSubject() const {
  ClearErrorOnReturn clearErrorOnReturn;
  if (cert_ == nullptr)
    return {};
  BIOPointer bio(BIO_new(BIO_s_mem()));
  if (!bio)
    return {};
  if (X509_NAME_print_ex(bio.get(), X509_get_subject_name(cert_), 0, kX509NameFlagsMultiline) <= 0) {
    return {};
  }
  return bio;
}

BIOPointer X509View::getSubjectAltName() const {
  ClearErrorOnReturn clearErrorOnReturn;
  if (cert_ == nullptr)
    return {};
  BIOPointer bio(BIO_new(BIO_s_mem()));
  if (!bio)
    return {};
  int index = X509_get_ext_by_NID(cert_, NID_subject_alt_name, -1);
  if (index < 0 || !SafeX509SubjectAltNamePrint(bio, X509_get_ext(cert_, index))) {
    return {};
  }
  return bio;
}

BIOPointer X509View::getIssuer() const {
  ClearErrorOnReturn clearErrorOnReturn;
  if (cert_ == nullptr)
    return {};
  BIOPointer bio(BIO_new(BIO_s_mem()));
  if (!bio)
    return {};
  if (X509_NAME_print_ex(bio.get(), X509_get_issuer_name(cert_), 0, kX509NameFlagsMultiline) <= 0) {
    return {};
  }
  return bio;
}

BIOPointer X509View::getInfoAccess() const {
  ClearErrorOnReturn clearErrorOnReturn;
  if (cert_ == nullptr)
    return {};
  BIOPointer bio(BIO_new(BIO_s_mem()));
  if (!bio)
    return {};
  int index = X509_get_ext_by_NID(cert_, NID_info_access, -1);
  if (index < 0)
    return {};
  if (!SafeX509InfoAccessPrint(bio, X509_get_ext(cert_, index))) {
    return {};
  }
  return bio;
}

BIOPointer X509View::getValidFrom() const {
  ClearErrorOnReturn clearErrorOnReturn;
  if (cert_ == nullptr)
    return {};
  BIOPointer bio(BIO_new(BIO_s_mem()));
  if (!bio)
    return {};
  ASN1_TIME_print(bio.get(), X509_get0_notBefore(cert_));
  return bio;
}

BIOPointer X509View::getValidTo() const {
  ClearErrorOnReturn clearErrorOnReturn;
  if (cert_ == nullptr)
    return {};
  BIOPointer bio(BIO_new(BIO_s_mem()));
  if (!bio)
    return {};
  ASN1_TIME_print(bio.get(), X509_get0_notAfter(cert_));
  return bio;
}

std::optional<std::string_view> X509View::getSignatureAlgorithm() const {
  if (cert_ == nullptr)
    return std::nullopt;
  int nid = X509_get_signature_nid(cert_);
  if (nid == NID_undef)
    return std::nullopt;
  const char* ln = OBJ_nid2ln(nid);
  if (ln == nullptr)
    return std::nullopt;
  return std::string_view(ln);
}

std::optional<std::string> X509View::getSignatureAlgorithmOID() const {
  if (cert_ == nullptr)
    return std::nullopt;
  const X509_ALGOR* alg = nullptr;
  X509_get0_signature(nullptr, &alg, cert_);
  if (alg == nullptr)
    return std::nullopt;
  const ASN1_OBJECT* obj = nullptr;
  X509_ALGOR_get0(&obj, nullptr, nullptr, alg);
  if (obj == nullptr)
    return std::nullopt;
  std::array<char, 128> buf{};
  int len = OBJ_obj2txt(buf.data(), buf.size(), obj, 1);
  if (len < 0 || static_cast<size_t>(len) >= buf.size())
    return std::nullopt;
  return std::string(buf.data(), static_cast<size_t>(len));
}

int64_t X509View::getValidToTime() const {
#ifdef OPENSSL_IS_BORINGSSL
#ifndef NCRYPTO_NO_ASN1_TIME
  // Boringssl does not implement ASN1_TIME_to_tm in a public way,
  // and only recently added ASN1_TIME_to_posix. Some boringssl
  // users on older version may still need to patch around this
  // or use a different implementation.
  int64_t tp;
  ASN1_TIME_to_posix(X509_get0_notAfter(cert_), &tp);
  return tp;
#else
  // Older versions of Boringssl do not implement the ASN1_TIME_to_*
  // version functions. For now, neither shall we.
  return 0LL;
#endif // NCRYPTO_NO_ASN1_TIME
#else  // OPENSSL_IS_BORINGSSL
  struct tm tp;
  ASN1_TIME_to_tm(X509_get0_notAfter(cert_), &tp);
  return PortableTimeGM(&tp);
#endif
}

int64_t X509View::getValidFromTime() const {
#ifdef OPENSSL_IS_BORINGSSL
#ifndef NCRYPTO_NO_ASN1_TIME
  int64_t tp;
  ASN1_TIME_to_posix(X509_get0_notBefore(cert_), &tp);
  return tp;
#else
  // Older versions of Boringssl do not implement the ASN1_TIME_to_*
  // version functions. For now, neither shall we.
  return 0LL;
#endif // NCRYPTO_NO_ASN1_TIME
#else
  struct tm tp;
  ASN1_TIME_to_tm(X509_get0_notBefore(cert_), &tp);
  return PortableTimeGM(&tp);
#endif
}

DataPointer X509View::getSerialNumber() const {
  ClearErrorOnReturn clearErrorOnReturn;
  if (cert_ == nullptr)
    return {};
  if (ASN1_INTEGER* serial_number = X509_get_serialNumber(const_cast<X509*>(cert_))) {
    if (auto bn = BignumPointer(ASN1_INTEGER_to_BN(serial_number, nullptr))) {
      return bn.toHex();
    }
  }
  return {};
}

Result<EVPKeyPointer, int> X509View::getPublicKey() const {
  ClearErrorOnReturn clearErrorOnReturn;
  if (cert_ == nullptr)
    return Result<EVPKeyPointer, int>(EVPKeyPointer{});
  auto pkey = EVPKeyPointer(X509_get_pubkey(const_cast<X509*>(cert_)));
  if (!pkey)
    return Result<EVPKeyPointer, int>(ERR_get_error());
  return pkey;
}

StackOfASN1 X509View::getKeyUsage() const {
  ClearErrorOnReturn clearErrorOnReturn;
  if (cert_ == nullptr)
    return {};
  return StackOfASN1(static_cast<STACK_OF(ASN1_OBJECT)*>(X509_get_ext_d2i(cert_, NID_ext_key_usage, nullptr, nullptr)));
}

bool X509View::isCA() const {
  ClearErrorOnReturn clearErrorOnReturn;
  if (cert_ == nullptr)
    return false;
  return X509_check_ca(const_cast<X509*>(cert_)) == 1;
}

bool X509View::isIssuedBy(const X509View& issuer) const {
  ClearErrorOnReturn clearErrorOnReturn;
  if (cert_ == nullptr || issuer.cert_ == nullptr)
    return false;
  return X509_check_issued(const_cast<X509*>(issuer.cert_), const_cast<X509*>(cert_)) == X509_V_OK;
}

bool X509View::checkPrivateKey(const EVPKeyPointer& pkey) const {
  ClearErrorOnReturn clearErrorOnReturn;
  if (cert_ == nullptr || pkey == nullptr)
    return false;
  return X509_check_private_key(const_cast<X509*>(cert_), pkey.get()) == 1;
}

bool X509View::checkPublicKey(const EVPKeyPointer& pkey) const {
  ClearErrorOnReturn clearErrorOnReturn;
  if (cert_ == nullptr || pkey == nullptr)
    return false;
  return X509_verify(const_cast<X509*>(cert_), pkey.get()) == 1;
}

X509View::CheckMatch X509View::checkHost(const std::string_view host, int flags, DataPointer* peerName) const {
  ClearErrorOnReturn clearErrorOnReturn;
  if (cert_ == nullptr)
    return CheckMatch::NO_MATCH;
  char* peername;
  switch (X509_check_host(const_cast<X509*>(cert_), host.data(), host.size(), flags, &peername)) {
    case 0:
      return CheckMatch::NO_MATCH;
    case 1: {
      if (peername != nullptr) {
        DataPointer name(peername, strlen(peername));
        if (peerName != nullptr)
          *peerName = std::move(name);
      }
      return CheckMatch::MATCH;
    }
    case -2:
      return CheckMatch::INVALID_NAME;
    default:
      return CheckMatch::OPERATION_FAILED;
  }
}

X509View::CheckMatch X509View::checkEmail(const std::string_view email, int flags) const {
  ClearErrorOnReturn clearErrorOnReturn;
  if (cert_ == nullptr)
    return CheckMatch::NO_MATCH;
  switch (X509_check_email(const_cast<X509*>(cert_), email.data(), email.size(), flags)) {
    case 0:
      return CheckMatch::NO_MATCH;
    case 1:
      return CheckMatch::MATCH;
    case -2:
      return CheckMatch::INVALID_NAME;
    default:
      return CheckMatch::OPERATION_FAILED;
  }
}

X509View::CheckMatch X509View::checkIp(const std::string_view ip, int flags) const {
  ClearErrorOnReturn clearErrorOnReturn;
  if (cert_ == nullptr)
    return CheckMatch::NO_MATCH;
  switch (X509_check_ip_asc(const_cast<X509*>(cert_), ip.data(), flags)) {
    case 0:
      return CheckMatch::NO_MATCH;
    case 1:
      return CheckMatch::MATCH;
    case -2:
      return CheckMatch::INVALID_NAME;
    default:
      return CheckMatch::OPERATION_FAILED;
  }
}

std::optional<std::string> X509View::getFingerprint(const Digest& method) const {
  unsigned int md_size;
  unsigned char md[EVP_MAX_MD_SIZE];
  static constexpr char hex[] = "0123456789ABCDEF";

  if (X509_digest(get(), method, md, &md_size)) {
    if (md_size == 0)
      return std::nullopt;
    std::string fingerprint((md_size * 3) - 1, 0);
    for (unsigned int i = 0; i < md_size; i++) {
      auto idx = 3 * i;
      fingerprint[idx] = hex[(md[i] & 0xf0) >> 4];
      fingerprint[idx + 1] = hex[(md[i] & 0x0f)];
      if (i == md_size - 1)
        break;
      fingerprint[idx + 2] = ':';
    }

    return fingerprint;
  }

  return std::nullopt;
}

Result<X509Pointer, int> X509Pointer::Parse(Buffer<const unsigned char> buffer) {
  ClearErrorOnReturn clearErrorOnReturn;
  BIOPointer bio(BIO_new_mem_buf(buffer.data, buffer.len));
  if (!bio)
    return Result<X509Pointer, int>(ERR_get_error());

  X509Pointer pem(PEM_read_bio_X509_AUX(bio.get(), nullptr, NoPasswordCallback, nullptr));
  if (pem)
    return Result<X509Pointer, int>(std::move(pem));
  if (!bio.resetBio())
    return Result<X509Pointer, int>(ERR_get_error());

  X509Pointer der(d2i_X509_bio(bio.get(), nullptr));
  if (der)
    return Result<X509Pointer, int>(std::move(der));

  return Result<X509Pointer, int>(ERR_get_error());
}

bool X509View::enumUsages(UsageCallback callback) const {
  if (cert_ == nullptr)
    return false;
  StackOfASN1 eku(static_cast<STACK_OF(ASN1_OBJECT)*>(X509_get_ext_d2i(cert_, NID_ext_key_usage, nullptr, nullptr)));
  if (!eku)
    return false;
  const int count = sk_ASN1_OBJECT_num(eku.get());
  char buf[256]{};

  for (int i = 0; i < count; i++) {
    if (OBJ_obj2txt(buf, sizeof(buf), sk_ASN1_OBJECT_value(eku.get(), i), 1) >= 0) {
      callback(buf);
    }
  }
  return true;
}

// When adding or removing errors below, please also update the list in the API
// documentation. See the "OpenSSL Error Codes" section of doc/api/errors.md
// Also *please* update the respective section in doc/api/tls.md as well
const char* X509Pointer::ErrorCode(int32_t err) { // NOLINT(runtime/int)
#define CASE(CODE)                                                                                                                         \
  case X509_V_ERR_##CODE:                                                                                                                  \
    return #CODE;
  switch (err) {
    CASE(UNABLE_TO_GET_ISSUER_CERT)
    CASE(UNABLE_TO_GET_CRL)
    CASE(UNABLE_TO_DECRYPT_CERT_SIGNATURE)
    CASE(UNABLE_TO_DECRYPT_CRL_SIGNATURE)
    CASE(UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY)
    CASE(CERT_SIGNATURE_FAILURE)
    CASE(CRL_SIGNATURE_FAILURE)
    CASE(CERT_NOT_YET_VALID)
    CASE(CERT_HAS_EXPIRED)
    CASE(CRL_NOT_YET_VALID)
    CASE(CRL_HAS_EXPIRED)
    CASE(ERROR_IN_CERT_NOT_BEFORE_FIELD)
    CASE(ERROR_IN_CERT_NOT_AFTER_FIELD)
    CASE(ERROR_IN_CRL_LAST_UPDATE_FIELD)
    CASE(ERROR_IN_CRL_NEXT_UPDATE_FIELD)
    CASE(OUT_OF_MEM)
    CASE(DEPTH_ZERO_SELF_SIGNED_CERT)
    CASE(SELF_SIGNED_CERT_IN_CHAIN)
    CASE(UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
    CASE(UNABLE_TO_VERIFY_LEAF_SIGNATURE)
    CASE(CERT_CHAIN_TOO_LONG)
    CASE(CERT_REVOKED)
    CASE(INVALID_CA)
    CASE(PATH_LENGTH_EXCEEDED)
    CASE(INVALID_PURPOSE)
    CASE(CERT_UNTRUSTED)
    CASE(CERT_REJECTED)
    CASE(HOSTNAME_MISMATCH)
  }
#undef CASE
  return "UNSPECIFIED";
}

std::optional<const char*> X509Pointer::ErrorReason(int32_t err) {
  if (err == X509_V_OK)
    return std::nullopt;
  return X509_verify_cert_error_string(err);
}

// ============================================================================
// BIOPointer

BIOPointer::BIOPointer(BIO* bio) : bio_(bio) {}

BIOPointer::BIOPointer(BIOPointer&& other) noexcept : bio_(other.release()) {}

BIOPointer& BIOPointer::operator=(BIOPointer&& other) noexcept {
  if (this == &other)
    return *this;
  this->~BIOPointer();
  return *new (this) BIOPointer(std::move(other));
}

BIOPointer::~BIOPointer() {
  reset();
}

void BIOPointer::reset(BIO* bio) {
  bio_.reset(bio);
}

BIO* BIOPointer::release() {
  return bio_.release();
}

bool BIOPointer::resetBio() const {
  if (!bio_)
    return 0;
  return BIO_reset(bio_.get()) == 1;
}

BIOPointer BIOPointer::NewMem() {
  return BIOPointer(BIO_new(BIO_s_mem()));
}

BIOPointer BIOPointer::NewSecMem() {
#ifdef OPENSSL_IS_BORINGSSL
  // Boringssl does not implement the BIO_s_secmem API.
  return BIOPointer(BIO_new(BIO_s_mem()));
#else
  return BIOPointer(BIO_new(BIO_s_secmem()));
#endif
}

BIOPointer BIOPointer::New(const BIO_METHOD* method) {
  if (method == nullptr)
    return {};
  return BIOPointer(BIO_new(method));
}

BIOPointer BIOPointer::New(const void* data, size_t len) {
  return BIOPointer(BIO_new_mem_buf(data, len));
}

BIOPointer BIOPointer::NewFile(const char* filename, const char* mode) {
  return BIOPointer(BIO_new_file(filename, mode));
}

BIOPointer BIOPointer::NewFp(FILE* fd, int close_flag) {
  return BIOPointer(BIO_new_fp(fd, close_flag));
}

BIOPointer BIOPointer::New(const BIGNUM* bn) {
  auto res = NewMem();
  if (!res || !BN_print(res.get(), bn))
    return {};
  return res;
}

int BIOPointer::Write(BIOPointer* bio, std::string_view message) {
  if (bio == nullptr || !*bio)
    return 0;
  return BIO_write(bio->get(), message.data(), message.size());
}

// ============================================================================
// KDF

const EVP_MD* getDigestByName(const char* name) {
  // Historically, "dss1" and "DSS1" were DSA aliases for SHA-1
  // exposed through the public API.
  if (strcmp(name, "dss1") == 0 || strcmp(name, "DSS1") == 0) [[unlikely]] {
    return EVP_sha1();
  }
  return EVP_get_digestbyname(name);
}

const EVP_CIPHER* getCipherByName(const char* name) {
  return EVP_get_cipherbyname(name);
}

bool checkHkdfLength(const Digest& md, size_t length) {
  // HKDF-Expand computes up to 255 HMAC blocks, each having as many bits as
  // the output of the hash function. 255 is a hard limit because HKDF appends
  // an 8-bit counter to each HMAC'd message, starting at 1.
  static constexpr size_t kMaxDigestMultiplier = 255;
  size_t max_length = md.size() * kMaxDigestMultiplier;
  if (length > max_length)
    return false;
  return true;
}

bool hkdfInfo(const Digest& md, const Buffer<const unsigned char>& key, const Buffer<const unsigned char>& info,
              const Buffer<const unsigned char>& salt, size_t length, Buffer<unsigned char>* out) {
  ClearErrorOnReturn clearErrorOnReturn;

  if (!checkHkdfLength(md, length) || info.len > INT_MAX || salt.len > INT_MAX) {
    return false;
  }

  std::string_view actual_salt;
  static const char default_salt[EVP_MAX_MD_SIZE] = {0};
  if (salt.len > 0) {
    actual_salt = {reinterpret_cast<const char*>(salt.data), salt.len};
  } else {
    actual_salt = {default_salt, static_cast<unsigned>(md.size())};
  }

#ifdef OPENSSL_IS_BORINGSSL
  if (out == nullptr || out->len != length)
    return false;
  return HKDF(out->data, length, md, key.data, key.len, reinterpret_cast<const unsigned char*>(actual_salt.data()), actual_salt.size(),
              info.data, info.len) == 1;
#else
  auto ctx = EVPKeyCtxPointer::NewFromID(EVP_PKEY_HKDF);
  // OpenSSL < 3.0.0 accepted only a void* as the argument of
  // EVP_PKEY_CTX_set_hkdf_md.
  const EVP_MD* md_ptr = md;
  if (!ctx || !EVP_PKEY_derive_init(ctx.get()) || !EVP_PKEY_CTX_set_hkdf_md(ctx.get(), md_ptr) ||
      !EVP_PKEY_CTX_add1_hkdf_info(ctx.get(), info.data, info.len)) {
    return false;
  }

  // We do not use EVP_PKEY_HKDF_MODE_EXTRACT_AND_EXPAND because and instead
  // implement the extraction step ourselves because EVP_PKEY_derive does not
  // handle zero-length keys, which are required for Web Crypto.
  // TODO(jasnell): Once OpenSSL 1.1.1 support is dropped completely, and once
  // BoringSSL is confirmed to support it, we can hopefully drop this and use
  // EVP_KDF directly which does support zero length keys.
  unsigned char pseudorandom_key[EVP_MAX_MD_SIZE];
  unsigned pseudorandom_key_len = sizeof(pseudorandom_key);

  if (HMAC(md, actual_salt.data(), actual_salt.size(), key.data, key.len, pseudorandom_key, &pseudorandom_key_len) == nullptr) {
    return false;
  }
  if (!EVP_PKEY_CTX_hkdf_mode(ctx.get(), EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) ||
      !EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), pseudorandom_key, pseudorandom_key_len)) {
    return false;
  }

  if (out == nullptr || out->len != length)
    return false;

  return EVP_PKEY_derive(ctx.get(), out->data, &length) > 0;
#endif
}

DataPointer hkdf(const Digest& md, const Buffer<const unsigned char>& key, const Buffer<const unsigned char>& info,
                 const Buffer<const unsigned char>& salt, size_t length) {
  auto buf = DataPointer::Alloc(length);
  if (!buf)
    return {};
  Buffer<unsigned char> out{
      .data = static_cast<unsigned char*>(buf.get()),
      .len = length,
  };
  if (hkdfInfo(md, key, info, salt, length, &out)) {
    return buf;
  }
  return {};
}

bool checkScryptParams(uint64_t N, uint64_t r, uint64_t p, uint64_t maxmem) {
  return EVP_PBE_scrypt(nullptr, 0, nullptr, 0, N, r, p, maxmem, nullptr, 0) == 1;
}

bool scryptInto(const Buffer<const char>& pass, const Buffer<const unsigned char>& salt, uint64_t N, uint64_t r, uint64_t p,
                uint64_t maxmem, size_t length, Buffer<unsigned char>* out) {
  ClearErrorOnReturn clearErrorOnReturn;

  if (pass.len > INT_MAX || salt.len > INT_MAX || out == nullptr) {
    return false;
  }

  return EVP_PBE_scrypt(pass.data, pass.len, salt.data, salt.len, N, r, p, maxmem, out->data, length) == 1;
}

DataPointer scrypt(const Buffer<const char>& pass, const Buffer<const unsigned char>& salt, uint64_t N, uint64_t r, uint64_t p,
                   uint64_t maxmem, size_t length) {
  ClearErrorOnReturn clearErrorOnReturn;

  if (pass.len > INT_MAX || salt.len > INT_MAX) {
    return {};
  }

  auto dp = DataPointer::Alloc(length);
  if (dp && EVP_PBE_scrypt(pass.data, pass.len, salt.data, salt.len, N, r, p, maxmem, reinterpret_cast<unsigned char*>(dp.get()), length)) {
    return dp;
  }

  return {};
}

bool pbkdf2Into(const Digest& md, const Buffer<const char>& pass, const Buffer<const unsigned char>& salt, uint32_t iterations,
                size_t length, Buffer<unsigned char>* out) {
  ClearErrorOnReturn clearErrorOnReturn;

  if (pass.len > INT_MAX || salt.len > INT_MAX || length > INT_MAX || out == nullptr) {
    return false;
  }

  const EVP_MD* md_ptr = md;
  return PKCS5_PBKDF2_HMAC(pass.data, pass.len, salt.data, salt.len, iterations, md_ptr, length, out->data) == 1;
}

DataPointer pbkdf2(const Digest& md, const Buffer<const char>& pass, const Buffer<const unsigned char>& salt, uint32_t iterations,
                   size_t length) {
  ClearErrorOnReturn clearErrorOnReturn;

  if (pass.len > INT_MAX || salt.len > INT_MAX || length > INT_MAX) {
    return {};
  }

  auto dp = DataPointer::Alloc(length);
  const EVP_MD* md_ptr = md;
  if (dp &&
      PKCS5_PBKDF2_HMAC(pass.data, pass.len, salt.data, salt.len, iterations, md_ptr, length, reinterpret_cast<unsigned char*>(dp.get()))) {
    return dp;
  }

  return {};
}

#if OPENSSL_VERSION_NUMBER >= 0x30200000L
#ifndef OPENSSL_NO_ARGON2
DataPointer argon2(const Buffer<const char>& pass, const Buffer<const unsigned char>& salt, uint32_t lanes, size_t length, uint32_t memcost,
                   uint32_t iter, uint32_t version, const Buffer<const unsigned char>& secret, const Buffer<const unsigned char>& ad,
                   Argon2Type type) {
  ClearErrorOnReturn clearErrorOnReturn;
  (void)version;

  std::string_view algorithm;
  switch (type) {
    case Argon2Type::ARGON2I:
      algorithm = "ARGON2I";
      break;
    case Argon2Type::ARGON2D:
      algorithm = "ARGON2D";
      break;
    case Argon2Type::ARGON2ID:
      algorithm = "ARGON2ID";
      break;
    default:
      // Invalid Argon2 type
      return {};
  }

  // creates a new library context to avoid locking when running concurrently
  auto ctx = DeleteFnPtr<OSSL_LIB_CTX, OSSL_LIB_CTX_free>{OSSL_LIB_CTX_new()};
  if (!ctx) {
    return {};
  }

  // required if threads > 1
  if (lanes > 1 && OSSL_set_max_threads(ctx.get(), lanes) != 1) {
    return {};
  }

  auto kdf = DeleteFnPtr<EVP_KDF, EVP_KDF_free>{EVP_KDF_fetch(ctx.get(), algorithm.data(), nullptr)};
  if (!kdf) {
    return {};
  }

  auto kctx = DeleteFnPtr<EVP_KDF_CTX, EVP_KDF_CTX_free>{EVP_KDF_CTX_new(kdf.get())};
  if (!kctx) {
    return {};
  }

  std::vector<OSSL_PARAM> params;
  params.reserve(9);

  params.push_back(OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, const_cast<char*>(pass.len > 0 ? pass.data : ""), pass.len));
  params.push_back(OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<unsigned char*>(salt.data), salt.len));
  params.push_back(OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, &lanes));
  params.push_back(OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &lanes));
  params.push_back(OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &memcost));
  params.push_back(OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iter));

  if (ad.len != 0) {
    params.push_back(OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_ARGON2_AD, const_cast<unsigned char*>(ad.data), ad.len));
  }

  if (secret.len != 0) {
    params.push_back(OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, const_cast<unsigned char*>(secret.data), secret.len));
  }

  params.push_back(OSSL_PARAM_construct_end());

  auto dp = DataPointer::Alloc(length);
  if (dp && EVP_KDF_derive(kctx.get(), reinterpret_cast<unsigned char*>(dp.get()), length, params.data()) == 1) {
    return dp;
  }

  return {};
}
#endif
#endif

// ============================================================================

EVPKeyPointer::PrivateKeyEncodingConfig::PrivateKeyEncodingConfig(const PrivateKeyEncodingConfig& other)
    : PrivateKeyEncodingConfig(other.output_key_object, other.format, other.type) {
  cipher = other.cipher;
  if (other.passphrase.has_value()) {
    auto& otherPassphrase = other.passphrase.value();
    auto newPassphrase = DataPointer::Alloc(otherPassphrase.size());
    memcpy(newPassphrase.get(), otherPassphrase.get(), otherPassphrase.size());
    passphrase = std::move(newPassphrase);
  }
}

EVPKeyPointer::AsymmetricKeyEncodingConfig::AsymmetricKeyEncodingConfig(bool output_key_object, PKFormatType format, PKEncodingType type)
    : output_key_object(output_key_object), format(format), type(type) {}

EVPKeyPointer::PrivateKeyEncodingConfig& EVPKeyPointer::PrivateKeyEncodingConfig::operator=(const PrivateKeyEncodingConfig& other) {
  if (this == &other)
    return *this;
  this->~PrivateKeyEncodingConfig();
  return *new (this) PrivateKeyEncodingConfig(other);
}

EVPKeyPointer EVPKeyPointer::New() {
  return EVPKeyPointer(EVP_PKEY_new());
}

EVPKeyPointer EVPKeyPointer::NewRawPublic(int id, const Buffer<const unsigned char>& data) {
  if (id == 0)
    return {};
  return EVPKeyPointer(EVP_PKEY_new_raw_public_key(id, nullptr, data.data, data.len));
}

EVPKeyPointer EVPKeyPointer::NewRawPrivate(int id, const Buffer<const unsigned char>& data) {
  if (id == 0)
    return {};
  return EVPKeyPointer(EVP_PKEY_new_raw_private_key(id, nullptr, data.data, data.len));
}

#if OPENSSL_WITH_PQC
EVPKeyPointer EVPKeyPointer::NewRawSeed(int id, const Buffer<const unsigned char>& data) {
  if (id == 0)
    return {};

  OSSL_PARAM params[] = {OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED, const_cast<unsigned char*>(data.data), data.len),
                         OSSL_PARAM_END};

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(id, nullptr);
  if (ctx == nullptr)
    return {};

  EVP_PKEY* pkey = nullptr;
  if (ctx == nullptr || EVP_PKEY_fromdata_init(ctx) <= 0 || EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return {};
  }

  return EVPKeyPointer(pkey);
}
#endif

EVPKeyPointer::EVPKeyPointer(EVP_PKEY* pkey) : pkey_(pkey) {}

EVPKeyPointer::EVPKeyPointer(EVPKeyPointer&& other) noexcept : pkey_(other.release()) {}

EVPKeyPointer& EVPKeyPointer::operator=(EVPKeyPointer&& other) noexcept {
  if (this == &other)
    return *this;
  this->~EVPKeyPointer();
  return *new (this) EVPKeyPointer(std::move(other));
}

EVPKeyPointer::~EVPKeyPointer() {
  reset();
}

void EVPKeyPointer::reset(EVP_PKEY* pkey) {
  pkey_.reset(pkey);
}

EVP_PKEY* EVPKeyPointer::release() {
  return pkey_.release();
}

int EVPKeyPointer::id(const EVP_PKEY* key) {
  if (key == nullptr)
    return 0;
  int type = EVP_PKEY_id(key);
#if OPENSSL_WITH_PQC
  // EVP_PKEY_id returns -1 when EVP_PKEY_* is only implemented in a provider
  // which is the case for all post-quantum NIST algorithms
  // one suggested way would be to use a chain of `EVP_PKEY_is_a`
  // https://github.com/openssl/openssl/issues/27738#issuecomment-3013215870
  // or, this way there are less calls to the OpenSSL provider, just
  // getting the name once
  if (type == -1) {
    const char* type_name = EVP_PKEY_get0_type_name(key);
    if (type_name == nullptr)
      return -1;

    for (const auto& mapping : pqc_mappings) {
      if (strcmp(type_name, mapping.name) == 0) {
        return mapping.nid;
      }
    }
  }
#endif
  return type;
}

int EVPKeyPointer::base_id(const EVP_PKEY* key) {
  if (key == nullptr)
    return 0;
  return EVP_PKEY_base_id(key);
}

int EVPKeyPointer::id() const {
  return id(get());
}

int EVPKeyPointer::base_id() const {
  return base_id(get());
}

int EVPKeyPointer::bits() const {
  if (get() == nullptr)
    return 0;
  return EVP_PKEY_bits(get());
}

size_t EVPKeyPointer::size() const {
  if (get() == nullptr)
    return 0;
  return EVP_PKEY_size(get());
}

EVPKeyCtxPointer EVPKeyPointer::newCtx() const {
  if (!pkey_)
    return {};
  return EVPKeyCtxPointer::New(*this);
}

size_t EVPKeyPointer::rawPublicKeySize() const {
  if (!pkey_)
    return 0;
  size_t len = 0;
  if (EVP_PKEY_get_raw_public_key(get(), nullptr, &len) == 1)
    return len;
  return 0;
}

size_t EVPKeyPointer::rawPrivateKeySize() const {
  if (!pkey_)
    return 0;
  size_t len = 0;
  if (EVP_PKEY_get_raw_private_key(get(), nullptr, &len) == 1)
    return len;
  return 0;
}

DataPointer EVPKeyPointer::rawPublicKey() const {
  if (!pkey_)
    return {};
  if (auto data = DataPointer::Alloc(rawPublicKeySize())) {
    const Buffer<unsigned char> buf = data;
    size_t len = data.size();
    if (EVP_PKEY_get_raw_public_key(get(), buf.data, &len) != 1)
      return {};
    return data;
  }
  return {};
}

#if OPENSSL_WITH_PQC
DataPointer EVPKeyPointer::rawSeed() const {
  if (!pkey_)
    return {};

  // Determine seed length and parameter name based on key type
  size_t seed_len;
  const char* param_name;

  switch (id()) {
    case EVP_PKEY_ML_DSA_44:
    case EVP_PKEY_ML_DSA_65:
    case EVP_PKEY_ML_DSA_87:
      seed_len = 32; // ML-DSA uses 32-byte seeds
      param_name = OSSL_PKEY_PARAM_ML_DSA_SEED;
      break;
    case EVP_PKEY_ML_KEM_512:
    case EVP_PKEY_ML_KEM_768:
    case EVP_PKEY_ML_KEM_1024:
      seed_len = 64; // ML-KEM uses 64-byte seeds
      param_name = OSSL_PKEY_PARAM_ML_KEM_SEED;
      break;
    default:
      unreachable();
  }

  if (auto data = DataPointer::Alloc(seed_len)) {
    const Buffer<unsigned char> buf = data;
    size_t len = data.size();

    if (EVP_PKEY_get_octet_string_param(get(), param_name, buf.data, len, &seed_len) != 1)
      return {};
    return data;
  }
  return {};
}
#endif

DataPointer EVPKeyPointer::rawPrivateKey() const {
  if (!pkey_)
    return {};
  if (auto data = DataPointer::Alloc(rawPrivateKeySize())) {
    const Buffer<unsigned char> buf = data;
    size_t len = data.size();
    if (EVP_PKEY_get_raw_private_key(get(), buf.data, &len) != 1)
      return {};
    return data;
  }
  return {};
}

BIOPointer EVPKeyPointer::derPublicKey() const {
  if (!pkey_)
    return {};
  auto bio = BIOPointer::NewMem();
  if (!bio)
    return {};
  if (!i2d_PUBKEY_bio(bio.get(), get()))
    return {};
  return bio;
}

namespace {
  EVPKeyPointer::ParseKeyResult TryParsePublicKeyInner(const BIOPointer& bp, const char* name, auto&& parse) {
    if (!bp.resetBio()) {
      return EVPKeyPointer::ParseKeyResult(EVPKeyPointer::PKParseError::FAILED);
    }
    unsigned char* der_data;
    long der_len; // NOLINT(runtime/int)

    // This skips surrounding data and decodes PEM to DER.
    {
      MarkPopErrorOnReturn mark_pop_error_on_return;
      if (PEM_bytes_read_bio(&der_data, &der_len, nullptr, name, bp.get(), nullptr, nullptr) != 1)
        return EVPKeyPointer::ParseKeyResult(EVPKeyPointer::PKParseError::NOT_RECOGNIZED);
    }
    DataPointer data(der_data, der_len);

    // OpenSSL might modify the pointer, so we need to make a copy before parsing.
    const unsigned char* p = der_data;
    EVPKeyPointer pkey(parse(&p, der_len));
    if (!pkey)
      return EVPKeyPointer::ParseKeyResult(EVPKeyPointer::PKParseError::FAILED);
    return EVPKeyPointer::ParseKeyResult(std::move(pkey));
  }

  constexpr bool IsASN1Sequence(const unsigned char* data, size_t size, size_t* data_offset, size_t* data_size) {
    if (size < 2 || data[0] != 0x30)
      return false;

    if (data[1] & 0x80) {
      // Long form.
      size_t n_bytes = data[1] & ~0x80;
      if (n_bytes + 2 > size || n_bytes > sizeof(size_t))
        return false;
      size_t length = 0;
      for (size_t i = 0; i < n_bytes; i++)
        length = (length << 8) | data[i + 2];
      *data_offset = 2 + n_bytes;
      *data_size = std::min(size - 2 - n_bytes, length);
    } else {
      // Short form.
      *data_offset = 2;
      *data_size = std::min<size_t>(size - 2, data[1]);
    }

    return true;
  }

  constexpr bool IsEncryptedPrivateKeyInfo(const Buffer<const unsigned char>& buffer) {
    // Both PrivateKeyInfo and EncryptedPrivateKeyInfo start with a SEQUENCE.
    if (buffer.len == 0 || buffer.data == nullptr)
      return false;
    size_t offset, len;
    if (!IsASN1Sequence(buffer.data, buffer.len, &offset, &len))
      return false;

    // A PrivateKeyInfo sequence always starts with an integer whereas an
    // EncryptedPrivateKeyInfo starts with an AlgorithmIdentifier.
    return len >= 1 && buffer.data[offset] != 2;
  }

} // namespace

bool EVPKeyPointer::IsRSAPrivateKey(const Buffer<const unsigned char>& buffer) {
  // Both RSAPrivateKey and RSAPublicKey structures start with a SEQUENCE.
  size_t offset, len;
  if (!IsASN1Sequence(buffer.data, buffer.len, &offset, &len))
    return false;

  // An RSAPrivateKey sequence always starts with a single-byte integer whose
  // value is either 0 or 1, whereas an RSAPublicKey starts with the modulus
  // (which is the product of two primes and therefore at least 4), so we can
  // decide the type of the structure based on the first three bytes of the
  // sequence.
  return len >= 3 && buffer.data[offset] == 2 && buffer.data[offset + 1] == 1 && !(buffer.data[offset + 2] & 0xfe);
}

EVPKeyPointer::ParseKeyResult EVPKeyPointer::TryParsePublicKeyPEM(const Buffer<const unsigned char>& buffer) {
  auto bp = BIOPointer::New(buffer.data, buffer.len);
  if (!bp)
    return ParseKeyResult(PKParseError::FAILED);

  // Try parsing as SubjectPublicKeyInfo (SPKI) first.
  if (auto ret = TryParsePublicKeyInner(bp, "PUBLIC KEY", [](const unsigned char** p, long l) { // NOLINT(runtime/int)
        return d2i_PUBKEY(nullptr, p, l);
      })) {
    return ret;
  }

  // Maybe it is PKCS#1.
  if (auto ret = TryParsePublicKeyInner(bp, "RSA PUBLIC KEY", [](const unsigned char** p, long l) { // NOLINT(runtime/int)
        return d2i_PublicKey(EVP_PKEY_RSA, nullptr, p, l);
      })) {
    return ret;
  }

  // X.509 fallback.
  if (auto ret = TryParsePublicKeyInner(bp, "CERTIFICATE", [](const unsigned char** p, long l) { // NOLINT(runtime/int)
        X509Pointer x509(d2i_X509(nullptr, p, l));
        return x509 ? X509_get_pubkey(x509.get()) : nullptr;
      })) {
    return ret;
  };

  return ParseKeyResult(PKParseError::NOT_RECOGNIZED);
}

EVPKeyPointer::ParseKeyResult EVPKeyPointer::TryParsePublicKey(const PublicKeyEncodingConfig& config,
                                                               const Buffer<const unsigned char>& buffer) {
  if (config.format == PKFormatType::PEM) {
    return TryParsePublicKeyPEM(buffer);
  }

  if (config.format != PKFormatType::DER) {
    return ParseKeyResult(PKParseError::FAILED);
  }

  const unsigned char* start = buffer.data;

  EVP_PKEY* key = nullptr;

  if (config.type == PKEncodingType::PKCS1 && (key = d2i_PublicKey(EVP_PKEY_RSA, nullptr, &start, buffer.len))) {
    return EVPKeyPointer::ParseKeyResult(EVPKeyPointer(key));
  }

  if (config.type == PKEncodingType::SPKI && (key = d2i_PUBKEY(nullptr, &start, buffer.len))) {
    return EVPKeyPointer::ParseKeyResult(EVPKeyPointer(key));
  }

  return ParseKeyResult(PKParseError::FAILED);
}

namespace {
  Buffer<char> GetPassphrase(const EVPKeyPointer::PrivateKeyEncodingConfig& config) {
    static char empty_passphrase;
    Buffer<char> pass{
        .data = &empty_passphrase,
        .len = 0,
    };
    if (config.passphrase.has_value()) {
      auto& passphrase = config.passphrase.value();
      // The pass.data can't be a nullptr, even if the len is zero or else
      // openssl will prompt for a password and we really don't want that.
      if (passphrase.get() != nullptr) {
        pass.data = static_cast<char*>(passphrase.get());
      }
      pass.len = passphrase.size();
    }
    return pass;
  }

  using EncoderCtxPointer = DeleteFnPtr<OSSL_ENCODER_CTX, OSSL_ENCODER_CTX_free>;

  bool EncodeTraditionalPemWithEmptyPassphrase(const EVP_PKEY* key, BIO* bio, int selection, const char* structure,
                                               const EVP_CIPHER* cipher) {
    BIOPointer der = BIOPointer::NewMem();
    EncoderCtxPointer encoder(OSSL_ENCODER_CTX_new_for_pkey(key, selection, "DER", structure, nullptr));
    if (!der || !encoder || OSSL_ENCODER_CTX_get_num_encoders(encoder.get()) == 0 || OSSL_ENCODER_to_bio(encoder.get(), der.get()) != 1) {
      return false;
    }

    BUF_MEM* der_data = der;
    const int iv_length = EVP_CIPHER_get_iv_length(cipher);
    const int key_length = EVP_CIPHER_get_key_length(cipher);
    const int block_size = EVP_CIPHER_get_block_size(cipher);
    if (der_data == nullptr || der_data->length > INT_MAX || iv_length <= 0 || iv_length > EVP_MAX_IV_LENGTH || key_length <= 0 ||
        key_length > EVP_MAX_KEY_LENGTH || block_size <= 0 || der_data->length > static_cast<size_t>(INT_MAX - block_size)) {
      return false;
    }

    std::array<unsigned char, EVP_MAX_IV_LENGTH> iv{};
    auto derived_key = DataPointer::SecureAlloc(key_length);
    auto encrypted = DataPointer::Alloc(der_data->length + block_size);
    auto ctx = CipherCtxPointer::New();
    const unsigned char empty_passphrase = 0;
    if (!derived_key || !encrypted || !ctx || RAND_bytes(iv.data(), iv_length) != 1 ||
        EVP_BytesToKey(cipher, EVP_md5(), iv.data(), &empty_passphrase, 0, 1, derived_key.get<unsigned char>(), nullptr) != key_length ||
        EVP_EncryptInit_ex(ctx.get(), cipher, nullptr, derived_key.get<unsigned char>(), iv.data()) != 1) {
      return false;
    }

    int encrypted_length = 0;
    int final_length = 0;
    if (EVP_EncryptUpdate(ctx.get(), encrypted.get<unsigned char>(), &encrypted_length,
                          reinterpret_cast<const unsigned char*>(der_data->data), static_cast<int>(der_data->length)) != 1 ||
        EVP_EncryptFinal_ex(ctx.get(), encrypted.get<unsigned char>() + encrypted_length, &final_length) != 1) {
      return false;
    }

    const char* pem_name;
    switch (EVP_PKEY_get_id(key)) {
      case EVP_PKEY_RSA:
        pem_name = "RSA PRIVATE KEY";
        break;
      case EVP_PKEY_EC:
        pem_name = "EC PRIVATE KEY";
        break;
      default:
        return false;
    }

    const char* cipher_name = EVP_CIPHER_get0_name(cipher);
    if (cipher_name == nullptr)
      return false;
    std::array<char, PEM_BUFSIZE> header{};
    PEM_proc_type(header.data(), PEM_TYPE_ENCRYPTED);
    PEM_dek_info(header.data(), cipher_name, iv_length, reinterpret_cast<const char*>(iv.data()));
    return PEM_write_bio(bio, pem_name, header.data(), encrypted.get<unsigned char>(), encrypted_length + final_length) > 0;
  }

  bool EncodeKey(const EVP_PKEY* key, BIO* bio, int selection, EVPKeyPointer::PKFormatType format, const char* structure,
                 const EVP_CIPHER* cipher = nullptr, Buffer<char> passphrase = {}) {
    const char* output_type;
    switch (format) {
      case EVPKeyPointer::PKFormatType::PEM:
        output_type = "PEM";
        break;
      case EVPKeyPointer::PKFormatType::DER:
        output_type = "DER";
        break;
      default:
        return false;
    }

    EncoderCtxPointer ctx(OSSL_ENCODER_CTX_new_for_pkey(key, selection, output_type, structure, nullptr));
    if (!ctx || OSSL_ENCODER_CTX_get_num_encoders(ctx.get()) == 0)
      return false;

    if (cipher != nullptr) {
      if (passphrase.len == 0) {
        // Provider PEM encoding rejects an empty password before encryption.
        // Provider DER plus EVP framing preserves the traditional PEM behavior.
        return EncodeTraditionalPemWithEmptyPassphrase(key, bio, selection, structure, cipher);
      }
      const char* cipher_name = EVP_CIPHER_get0_name(cipher);
      if (cipher_name == nullptr || OSSL_ENCODER_CTX_set_cipher(ctx.get(), cipher_name, nullptr) != 1 ||
          OSSL_ENCODER_CTX_set_passphrase(ctx.get(), reinterpret_cast<const unsigned char*>(passphrase.data), passphrase.len) != 1) {
        return false;
      }
    }

    return OSSL_ENCODER_to_bio(ctx.get(), bio) == 1;
  }
} // namespace

EVPKeyPointer::ParseKeyResult EVPKeyPointer::TryParsePrivateKey(const PrivateKeyEncodingConfig& config,
                                                                const Buffer<const unsigned char>& buffer) {
  static constexpr auto keyOrError = [](EVPKeyPointer pkey, bool had_passphrase = false) {
    if (int err = ERR_peek_error()) {
      if (ERR_GET_LIB(err) == ERR_LIB_PEM && ERR_GET_REASON(err) == PEM_R_BAD_PASSWORD_READ && !had_passphrase) {
        return ParseKeyResult(PKParseError::NEED_PASSPHRASE);
      }
      return ParseKeyResult(PKParseError::FAILED, err);
    }
    if (!pkey)
      return ParseKeyResult(PKParseError::FAILED);
    return ParseKeyResult(std::move(pkey));
  };

  auto bio = BIOPointer::New(buffer);
  if (!bio)
    return ParseKeyResult(PKParseError::FAILED);

  auto passphrase = GetPassphrase(config);

  if (config.format == PKFormatType::PEM) {
    auto key = PEM_read_bio_PrivateKey(bio.get(), nullptr, PasswordCallback, config.passphrase.has_value() ? &passphrase : nullptr);
    return keyOrError(EVPKeyPointer(key), config.passphrase.has_value());
  }

  if (config.format != PKFormatType::DER) {
    return ParseKeyResult(PKParseError::FAILED);
  }

  switch (config.type) {
    case PKEncodingType::PKCS1: {
      auto key = d2i_PrivateKey_bio(bio.get(), nullptr);
      return keyOrError(EVPKeyPointer(key));
    }
    case PKEncodingType::PKCS8: {
      if (IsEncryptedPrivateKeyInfo(buffer)) {
        auto key = d2i_PKCS8PrivateKey_bio(bio.get(), nullptr, PasswordCallback, config.passphrase.has_value() ? &passphrase : nullptr);
        return keyOrError(EVPKeyPointer(key), config.passphrase.has_value());
      }

      PKCS8Pointer p8inf(d2i_PKCS8_PRIV_KEY_INFO_bio(bio.get(), nullptr));
      if (!p8inf) {
        return ParseKeyResult(PKParseError::FAILED, ERR_peek_error());
      }
      return keyOrError(EVPKeyPointer(EVP_PKCS82PKEY(p8inf.get())));
    }
    case PKEncodingType::SEC1: {
      auto key = d2i_PrivateKey_bio(bio.get(), nullptr);
      return keyOrError(EVPKeyPointer(key));
    }
    default: {
      return ParseKeyResult(PKParseError::FAILED, ERR_peek_error());
    }
  };
}

Result<BIOPointer, bool> EVPKeyPointer::writePrivateKey(const PrivateKeyEncodingConfig& config) const {
  if (config.format == PKFormatType::JWK) {
    return Result<BIOPointer, bool>(false);
  }

  auto bio = BIOPointer::NewMem();
  if (!bio) {
    return Result<BIOPointer, bool>(false);
  }

  auto passphrase = GetPassphrase(config);
  MarkPopErrorOnReturn mark_pop_error_on_return;
  bool err;

  switch (config.type) {
    case PKEncodingType::PKCS1: {
      // PKCS1 is only permitted for RSA keys.
      if (id() != EVP_PKEY_RSA)
        return Result<BIOPointer, bool>(false);
      const EVP_CIPHER* cipher = config.format == PKFormatType::PEM ? config.cipher : nullptr;
      err = !EncodeKey(get(), bio.get(), EVP_PKEY_KEYPAIR, config.format, "type-specific", cipher, passphrase);
      break;
    }
    case PKEncodingType::PKCS8: {
      switch (config.format) {
        case PKFormatType::PEM: {
          // Encode PKCS#8 as PEM.
          err = PEM_write_bio_PKCS8PrivateKey(bio.get(), get(), config.cipher, passphrase.data, passphrase.len, nullptr, nullptr) != 1;
          break;
        }
        case PKFormatType::DER: {
          err = i2d_PKCS8PrivateKey_bio(bio.get(), get(), config.cipher, passphrase.data, passphrase.len, nullptr, nullptr) != 1;
          break;
        }
        default: {
          // Should never get here.
          return Result<BIOPointer, bool>(false);
        }
      }
      break;
    }
    case PKEncodingType::SEC1: {
      // SEC1 is only permitted for EC keys
      if (id() != EVP_PKEY_EC)
        return Result<BIOPointer, bool>(false);
      const EVP_CIPHER* cipher = config.format == PKFormatType::PEM ? config.cipher : nullptr;
      err = !EncodeKey(get(), bio.get(), EVP_PKEY_KEYPAIR, config.format, "type-specific", cipher, passphrase);
      break;
    }
    default: {
      // Not a valid private key encoding
      return Result<BIOPointer, bool>(false);
    }
  }

  if (err) {
    // Failed to encode the private key.
    return Result<BIOPointer, bool>(false, mark_pop_error_on_return.peekError());
  }

  return bio;
}

Result<BIOPointer, bool> EVPKeyPointer::writePublicKey(const ncrypto::EVPKeyPointer::PublicKeyEncodingConfig& config) const {
  auto bio = BIOPointer::NewMem();
  if (!bio)
    return Result<BIOPointer, bool>(false);

  MarkPopErrorOnReturn mark_pop_error_on_return;

  if (config.type == ncrypto::EVPKeyPointer::PKEncodingType::PKCS1) {
    // PKCS#1 is only valid for RSA keys.
    if (id() != EVP_PKEY_RSA || !EncodeKey(get(), bio.get(), EVP_PKEY_PUBLIC_KEY, config.format, "type-specific")) {
      return Result<BIOPointer, bool>(false, mark_pop_error_on_return.peekError());
    }
    return bio;
  }

  if (config.format == ncrypto::EVPKeyPointer::PKFormatType::PEM) {
    // Encode SPKI as PEM.
    if (PEM_write_bio_PUBKEY(bio.get(), get()) != 1) {
      return Result<BIOPointer, bool>(false, mark_pop_error_on_return.peekError());
    }
    return bio;
  }

  // Encode SPKI as DER.
  if (i2d_PUBKEY_bio(bio.get(), get()) != 1) {
    return Result<BIOPointer, bool>(false, mark_pop_error_on_return.peekError());
  }
  return bio;
}

bool EVPKeyPointer::isRsaVariant() const {
  if (!pkey_)
    return false;
  int type = id();
  return type == EVP_PKEY_RSA || type == EVP_PKEY_RSA2 || type == EVP_PKEY_RSA_PSS;
}

bool EVPKeyPointer::isOneShotVariant() const {
  if (!pkey_)
    return false;
  int type = id();
  switch (type) {
    case EVP_PKEY_ED25519:
    case EVP_PKEY_ED448:
#if OPENSSL_WITH_PQC
    case EVP_PKEY_ML_DSA_44:
    case EVP_PKEY_ML_DSA_65:
    case EVP_PKEY_ML_DSA_87:
    case EVP_PKEY_SLH_DSA_SHA2_128F:
    case EVP_PKEY_SLH_DSA_SHA2_128S:
    case EVP_PKEY_SLH_DSA_SHA2_192F:
    case EVP_PKEY_SLH_DSA_SHA2_192S:
    case EVP_PKEY_SLH_DSA_SHA2_256F:
    case EVP_PKEY_SLH_DSA_SHA2_256S:
    case EVP_PKEY_SLH_DSA_SHAKE_128F:
    case EVP_PKEY_SLH_DSA_SHAKE_128S:
    case EVP_PKEY_SLH_DSA_SHAKE_192F:
    case EVP_PKEY_SLH_DSA_SHAKE_192S:
    case EVP_PKEY_SLH_DSA_SHAKE_256F:
    case EVP_PKEY_SLH_DSA_SHAKE_256S:
#endif
      return true;
    default:
      return false;
  }
}

bool EVPKeyPointer::isSigVariant() const {
  if (!pkey_)
    return false;
  int type = id();
  return type == EVP_PKEY_EC || type == EVP_PKEY_DSA;
}

int EVPKeyPointer::getDefaultSignPadding() const {
  return id() == EVP_PKEY_RSA_PSS ? RSA_PKCS1_PSS_PADDING : RSA_PKCS1_PADDING;
}

std::optional<uint32_t> EVPKeyPointer::getBytesOfRS() const {
  if (!pkey_)
    return std::nullopt;
  const char* parameter;

  switch (base_id()) {
    case EVP_PKEY_DSA:
      parameter = OSSL_PKEY_PARAM_FFC_Q;
      break;
    case EVP_PKEY_EC:
      parameter = OSSL_PKEY_PARAM_EC_ORDER;
      break;
    default:
      return std::nullopt;
  }

  BIGNUM* raw = nullptr;
  if (EVP_PKEY_get_bn_param(get(), parameter, &raw) != 1) {
    return std::nullopt;
  }
  BignumPointer value(raw);
  return (value.bitLength() + 7) / 8;
}

EVPKeyPointer EVPKeyPointer::clone() const {
  if (!pkey_)
    return {};
  if (!EVP_PKEY_up_ref(pkey_.get()))
    return {};
  return EVPKeyPointer(pkey_.get());
}

bool EVPKeyPointer::validateDsaParameters() const {
  if (!pkey_)
    return false;
  if (EVP_default_properties_is_fips_enabled(nullptr) && EVP_PKEY_DSA == id()) {
    BIGNUM* raw_p = nullptr;
    BIGNUM* raw_q = nullptr;
    if (EVP_PKEY_get_bn_param(get(), OSSL_PKEY_PARAM_FFC_P, &raw_p) != 1 ||
        EVP_PKEY_get_bn_param(get(), OSSL_PKEY_PARAM_FFC_Q, &raw_q) != 1) {
      BN_clear_free(raw_p);
      BN_clear_free(raw_q);
      return false;
    }
    BignumPointer p(raw_p);
    BignumPointer q(raw_q);
    int L = p.bitLength();
    int N = q.bitLength();

    return (L == 1024 && N == 160) || (L == 2048 && N == 224) || (L == 2048 && N == 256) || (L == 3072 && N == 256);
  }

  return true;
}

// ============================================================================

const Cipher Cipher::FromName(const char* name) {
  return Cipher(EVP_get_cipherbyname(name));
}

const Cipher Cipher::FromNid(int nid) {
  return Cipher(EVP_get_cipherbynid(nid));
}

const Cipher Cipher::FromCtx(const CipherCtxPointer& ctx) {
  return Cipher(EVP_CIPHER_CTX_cipher(ctx.get()));
}

const Cipher Cipher::EMPTY = Cipher();
const Cipher Cipher::AES_128_CBC = Cipher::FromNid(NID_aes_128_cbc);
const Cipher Cipher::AES_192_CBC = Cipher::FromNid(NID_aes_192_cbc);
const Cipher Cipher::AES_256_CBC = Cipher::FromNid(NID_aes_256_cbc);
const Cipher Cipher::AES_128_CTR = Cipher::FromNid(NID_aes_128_ctr);
const Cipher Cipher::AES_192_CTR = Cipher::FromNid(NID_aes_192_ctr);
const Cipher Cipher::AES_256_CTR = Cipher::FromNid(NID_aes_256_ctr);
const Cipher Cipher::AES_128_GCM = Cipher::FromNid(NID_aes_128_gcm);
const Cipher Cipher::AES_192_GCM = Cipher::FromNid(NID_aes_192_gcm);
const Cipher Cipher::AES_256_GCM = Cipher::FromNid(NID_aes_256_gcm);
const Cipher Cipher::AES_128_KW = Cipher::FromNid(NID_id_aes128_wrap);
const Cipher Cipher::AES_192_KW = Cipher::FromNid(NID_id_aes192_wrap);
const Cipher Cipher::AES_256_KW = Cipher::FromNid(NID_id_aes256_wrap);

#ifndef OPENSSL_IS_BORINGSSL
const Cipher Cipher::AES_128_OCB = Cipher::FromNid(NID_aes_128_ocb);
const Cipher Cipher::AES_192_OCB = Cipher::FromNid(NID_aes_192_ocb);
const Cipher Cipher::AES_256_OCB = Cipher::FromNid(NID_aes_256_ocb);
#endif

const Cipher Cipher::CHACHA20_POLY1305 = Cipher::FromNid(NID_chacha20_poly1305);

bool Cipher::isGcmMode() const {
  if (!cipher_)
    return false;
  return getMode() == EVP_CIPH_GCM_MODE;
}

bool Cipher::isWrapMode() const {
  if (!cipher_)
    return false;
  return getMode() == EVP_CIPH_WRAP_MODE;
}

bool Cipher::isCtrMode() const {
  if (!cipher_)
    return false;
  return getMode() == EVP_CIPH_CTR_MODE;
}

bool Cipher::isCcmMode() const {
  if (!cipher_)
    return false;
  return getMode() == EVP_CIPH_CCM_MODE;
}

bool Cipher::isOcbMode() const {
  if (!cipher_)
    return false;
  return getMode() == EVP_CIPH_OCB_MODE;
}

bool Cipher::isStreamMode() const {
  if (!cipher_)
    return false;
  return getMode() == EVP_CIPH_STREAM_CIPHER;
}

bool Cipher::isChaCha20Poly1305() const {
  if (!cipher_)
    return false;
  return getNid() == NID_chacha20_poly1305;
}

int Cipher::getMode() const {
  if (!cipher_)
    return 0;
  return EVP_CIPHER_mode(cipher_);
}

int Cipher::getIvLength() const {
  if (!cipher_)
    return 0;
  return EVP_CIPHER_iv_length(cipher_);
}

int Cipher::getKeyLength() const {
  if (!cipher_)
    return 0;
  return EVP_CIPHER_key_length(cipher_);
}

int Cipher::getBlockSize() const {
  if (!cipher_)
    return 0;
  return EVP_CIPHER_block_size(cipher_);
}

int Cipher::getNid() const {
  if (!cipher_)
    return 0;
  return EVP_CIPHER_nid(cipher_);
}

std::string_view Cipher::getModeLabel() const {
  if (!cipher_)
    return {};
  switch (getMode()) {
    case EVP_CIPH_CCM_MODE:
      return "ccm";
    case EVP_CIPH_CFB_MODE:
      return "cfb";
    case EVP_CIPH_CBC_MODE:
      return "cbc";
    case EVP_CIPH_CTR_MODE:
      return "ctr";
    case EVP_CIPH_ECB_MODE:
      return "ecb";
    case EVP_CIPH_GCM_MODE:
      return "gcm";
    case EVP_CIPH_OCB_MODE:
      return "ocb";
    case EVP_CIPH_OFB_MODE:
      return "ofb";
    case EVP_CIPH_WRAP_MODE:
      return "wrap";
    case EVP_CIPH_XTS_MODE:
      return "xts";
    case EVP_CIPH_STREAM_CIPHER:
      return "stream";
  }
  return "{unknown}";
}

const char* Cipher::getName() const {
  if (!cipher_)
    return {};
  // OBJ_nid2sn(EVP_CIPHER_nid(cipher)) is used here instead of
  // EVP_CIPHER_name(cipher) for compatibility with BoringSSL.
  return OBJ_nid2sn(getNid());
}

bool Cipher::isSupportedAuthenticatedMode() const {
  switch (getMode()) {
    case EVP_CIPH_CCM_MODE:
    case EVP_CIPH_GCM_MODE:
#ifndef OPENSSL_NO_OCB
    case EVP_CIPH_OCB_MODE:
#endif
      return true;
    case EVP_CIPH_STREAM_CIPHER:
      return getNid() == NID_chacha20_poly1305;
    default:
      return false;
  }
}

int Cipher::bytesToKey(const Digest& digest, const Buffer<const unsigned char>& input, unsigned char* key, unsigned char* iv) const {
  return EVP_BytesToKey(*this, digest, nullptr, input.data, input.len, 1, key, iv);
}

// ============================================================================

CipherCtxPointer CipherCtxPointer::New() {
  auto ret = CipherCtxPointer(EVP_CIPHER_CTX_new());
  if (!ret)
    return {};
  EVP_CIPHER_CTX_init(ret.get());
  return ret;
}

CipherCtxPointer::CipherCtxPointer(EVP_CIPHER_CTX* ctx) : ctx_(ctx) {}

CipherCtxPointer::CipherCtxPointer(CipherCtxPointer&& other) noexcept : ctx_(other.release()) {}

CipherCtxPointer& CipherCtxPointer::operator=(CipherCtxPointer&& other) noexcept {
  if (this == &other)
    return *this;
  this->~CipherCtxPointer();
  return *new (this) CipherCtxPointer(std::move(other));
}

CipherCtxPointer::~CipherCtxPointer() {
  reset();
}

void CipherCtxPointer::reset(EVP_CIPHER_CTX* ctx) {
  ctx_.reset(ctx);
}

EVP_CIPHER_CTX* CipherCtxPointer::release() {
  return ctx_.release();
}

void CipherCtxPointer::setAllowWrap() {
  if (!ctx_)
    return;
  EVP_CIPHER_CTX_set_flags(ctx_.get(), EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
}

bool CipherCtxPointer::setKeyLength(size_t length) {
  if (!ctx_)
    return false;
  return EVP_CIPHER_CTX_set_key_length(ctx_.get(), length);
}

bool CipherCtxPointer::setIvLength(size_t length) {
  if (!ctx_)
    return false;
  return EVP_CIPHER_CTX_ctrl(ctx_.get(), EVP_CTRL_AEAD_SET_IVLEN, length, nullptr) > 0;
}

bool CipherCtxPointer::setAeadTag(const Buffer<const char>& tag) {
  if (!ctx_)
    return false;
  return EVP_CIPHER_CTX_ctrl(ctx_.get(), EVP_CTRL_AEAD_SET_TAG, tag.len, const_cast<char*>(tag.data)) > 0;
}

bool CipherCtxPointer::setAeadTagLength(size_t length) {
  if (!ctx_)
    return false;
  return EVP_CIPHER_CTX_ctrl(ctx_.get(), EVP_CTRL_AEAD_SET_TAG, length, nullptr) > 0;
}

bool CipherCtxPointer::setPadding(bool padding) {
  if (!ctx_)
    return false;
  return EVP_CIPHER_CTX_set_padding(ctx_.get(), padding);
}

int CipherCtxPointer::getBlockSize() const {
  if (!ctx_)
    return 0;
  return EVP_CIPHER_CTX_block_size(ctx_.get());
}

int CipherCtxPointer::getMode() const {
  if (!ctx_)
    return 0;
  return EVP_CIPHER_CTX_mode(ctx_.get());
}

bool CipherCtxPointer::isGcmMode() const {
  if (!ctx_)
    return false;
  return getMode() == EVP_CIPH_GCM_MODE;
}

bool CipherCtxPointer::isOcbMode() const {
  if (!ctx_)
    return false;
  return getMode() == EVP_CIPH_OCB_MODE;
}

bool CipherCtxPointer::isCcmMode() const {
  if (!ctx_)
    return false;
  return getMode() == EVP_CIPH_CCM_MODE;
}

bool CipherCtxPointer::isWrapMode() const {
  if (!ctx_)
    return false;
  return getMode() == EVP_CIPH_WRAP_MODE;
}

bool CipherCtxPointer::isChaCha20Poly1305() const {
  if (!ctx_)
    return false;
  return getNid() == NID_chacha20_poly1305;
}

int CipherCtxPointer::getNid() const {
  if (!ctx_)
    return 0;
  return EVP_CIPHER_CTX_nid(ctx_.get());
}

bool CipherCtxPointer::init(const Cipher& cipher, bool encrypt, const unsigned char* key, const unsigned char* iv) {
  if (!ctx_)
    return false;
  return EVP_CipherInit_ex(ctx_.get(), cipher, nullptr, key, iv, encrypt ? 1 : 0) == 1;
}

bool CipherCtxPointer::update(const Buffer<const unsigned char>& in, unsigned char* out, int* out_len, bool finalize) {
  if (!ctx_)
    return false;
  if (!finalize) {
    return EVP_CipherUpdate(ctx_.get(), out, out_len, in.data, in.len) == 1;
  }
  return EVP_CipherFinal_ex(ctx_.get(), out, out_len) == 1;
}

bool CipherCtxPointer::getAeadTag(size_t len, unsigned char* out) {
  if (!ctx_)
    return false;
  return EVP_CIPHER_CTX_ctrl(ctx_.get(), EVP_CTRL_AEAD_GET_TAG, len, out) > 0;
}

// ============================================================================

ECDSASigPointer::ECDSASigPointer() : sig_(nullptr) {}
ECDSASigPointer::ECDSASigPointer(ECDSA_SIG* sig) : sig_(sig) {
  if (sig_) {
    ECDSA_SIG_get0(sig_.get(), &pr_, &ps_);
  }
}
ECDSASigPointer::ECDSASigPointer(ECDSASigPointer&& other) noexcept : sig_(other.release()) {
  if (sig_) {
    ECDSA_SIG_get0(sig_.get(), &pr_, &ps_);
  }
}

ECDSASigPointer& ECDSASigPointer::operator=(ECDSASigPointer&& other) noexcept {
  sig_.reset(other.release());
  if (sig_) {
    ECDSA_SIG_get0(sig_.get(), &pr_, &ps_);
  }
  return *this;
}

ECDSASigPointer::~ECDSASigPointer() {
  reset();
}

void ECDSASigPointer::reset(ECDSA_SIG* sig) {
  sig_.reset(sig);
  pr_ = nullptr;
  ps_ = nullptr;
}

ECDSA_SIG* ECDSASigPointer::release() {
  pr_ = nullptr;
  ps_ = nullptr;
  return sig_.release();
}

ECDSASigPointer ECDSASigPointer::New() {
  return ECDSASigPointer(ECDSA_SIG_new());
}

ECDSASigPointer ECDSASigPointer::Parse(const Buffer<const unsigned char>& sig) {
  const unsigned char* ptr = sig.data;
  return ECDSASigPointer(d2i_ECDSA_SIG(nullptr, &ptr, sig.len));
}

bool ECDSASigPointer::setParams(BignumPointer&& r, BignumPointer&& s) {
  if (!sig_)
    return false;
  return ECDSA_SIG_set0(sig_.get(), r.release(), s.release());
}

Buffer<unsigned char> ECDSASigPointer::encode() const {
  if (!sig_)
    return {
        .data = nullptr,
        .len = 0,
    };
  Buffer<unsigned char> buf;
  buf.len = i2d_ECDSA_SIG(sig_.get(), &buf.data);
  return buf;
}

// ============================================================================

EVPKeyCtxPointer::EVPKeyCtxPointer() : ctx_(nullptr) {}

EVPKeyCtxPointer::EVPKeyCtxPointer(EVP_PKEY_CTX* ctx) : ctx_(ctx) {}

EVPKeyCtxPointer::EVPKeyCtxPointer(EVPKeyCtxPointer&& other) noexcept : ctx_(other.release()) {}

EVPKeyCtxPointer& EVPKeyCtxPointer::operator=(EVPKeyCtxPointer&& other) noexcept {
  ctx_.reset(other.release());
  return *this;
}

EVPKeyCtxPointer::~EVPKeyCtxPointer() {
  reset();
}

void EVPKeyCtxPointer::reset(EVP_PKEY_CTX* ctx) {
  ctx_.reset(ctx);
}

EVP_PKEY_CTX* EVPKeyCtxPointer::release() {
  return ctx_.release();
}

EVPKeyCtxPointer EVPKeyCtxPointer::New(const EVPKeyPointer& key) {
  if (!key)
    return {};
  return EVPKeyCtxPointer(EVP_PKEY_CTX_new(key.get(), nullptr));
}

EVPKeyCtxPointer EVPKeyCtxPointer::NewFromID(int id) {
#ifdef OPENSSL_IS_BORINGSSL
  // DSA keys are not supported with BoringSSL
  if (id == EVP_PKEY_DSA)
    return {};
#endif
  return EVPKeyCtxPointer(EVP_PKEY_CTX_new_id(id, nullptr));
}

bool EVPKeyCtxPointer::initForDerive(const EVPKeyPointer& peer) {
  if (!ctx_)
    return false;
  if (EVP_PKEY_derive_init(ctx_.get()) != 1)
    return false;
  return EVP_PKEY_derive_set_peer(ctx_.get(), peer.get()) == 1;
}

bool EVPKeyCtxPointer::initForKeygen() {
  if (!ctx_)
    return false;
  return EVP_PKEY_keygen_init(ctx_.get()) == 1;
}

bool EVPKeyCtxPointer::initForParamgen() {
  if (!ctx_)
    return false;
  return EVP_PKEY_paramgen_init(ctx_.get()) == 1;
}

int EVPKeyCtxPointer::initForVerify() {
  if (!ctx_)
    return 0;
  return EVP_PKEY_verify_init(ctx_.get());
}

int EVPKeyCtxPointer::initForSign() {
  if (!ctx_)
    return 0;
  return EVP_PKEY_sign_init(ctx_.get());
}

bool EVPKeyCtxPointer::setDhParameters(int prime_size, uint32_t generator) {
#ifndef OPENSSL_IS_BORINGSSL
  if (!ctx_)
    return false;
  return EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx_.get(), prime_size) == 1 &&
         EVP_PKEY_CTX_set_dh_paramgen_generator(ctx_.get(), generator) == 1;
#else
  // TODO(jasnell): Boringssl appears not to support this operation.
  // Is there an alternative approach that Boringssl does support?
  return false;
#endif
}

bool EVPKeyCtxPointer::setDsaParameters(uint32_t bits, std::optional<int> q_bits) {
#ifndef NCRYPTO_NO_DSA_KEYGEN
  if (!ctx_)
    return false;
  if (EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx_.get(), bits) != 1) {
    return false;
  }
  if (q_bits.has_value() && EVP_PKEY_CTX_set_dsa_paramgen_q_bits(ctx_.get(), q_bits.value()) != 1) {
    return false;
  }
  return true;
#else
  // Older versions of openssl/boringssl do not implement the DSA keygen.
  return false;
#endif
}

bool EVPKeyCtxPointer::setEcParameters(int curve, int encoding) {
  if (!ctx_)
    return false;
  return EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx_.get(), curve) == 1 && EVP_PKEY_CTX_set_ec_param_enc(ctx_.get(), encoding) == 1;
}

bool EVPKeyCtxPointer::setRsaOaepMd(const Digest& md) {
  if (!md || !ctx_)
    return false;
  const EVP_MD* md_ptr = md;
  return EVP_PKEY_CTX_set_rsa_oaep_md(ctx_.get(), md_ptr) > 0;
}

bool EVPKeyCtxPointer::setRsaMgf1Md(const Digest& md) {
  if (!md || !ctx_)
    return false;
  const EVP_MD* md_ptr = md;
  return EVP_PKEY_CTX_set_rsa_mgf1_md(ctx_.get(), md_ptr) > 0;
}

bool EVPKeyCtxPointer::setRsaPadding(int padding) {
  return setRsaPadding(ctx_.get(), padding, std::nullopt);
}

bool EVPKeyCtxPointer::setRsaPadding(EVP_PKEY_CTX* ctx, int padding, std::optional<int> salt_len) {
  if (ctx == nullptr)
    return false;
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0) {
    return false;
  }
  if (padding == RSA_PKCS1_PSS_PADDING && salt_len.has_value()) {
    return EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, salt_len.value()) > 0;
  }
  return true;
}

bool EVPKeyCtxPointer::setRsaKeygenBits(int bits) {
  if (!ctx_)
    return false;
  return EVP_PKEY_CTX_set_rsa_keygen_bits(ctx_.get(), bits) == 1;
}

bool EVPKeyCtxPointer::setRsaKeygenPubExp(BignumPointer&& e) {
  if (!ctx_)
    return false;
  return EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx_.get(), e.get()) == 1;
}

bool EVPKeyCtxPointer::setRsaPssKeygenMd(const Digest& md) {
  if (!md || !ctx_)
    return false;
  // OpenSSL < 3 accepts a void* for the md parameter.
  const EVP_MD* md_ptr = md;
  return EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx_.get(), md_ptr) > 0;
}

bool EVPKeyCtxPointer::setRsaPssKeygenMgf1Md(const Digest& md) {
  if (!md || !ctx_)
    return false;
  const EVP_MD* md_ptr = md;
  return EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(ctx_.get(), md_ptr) > 0;
}

bool EVPKeyCtxPointer::setRsaPssSaltlen(int salt_len) {
  if (!ctx_)
    return false;
  return EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx_.get(), salt_len) > 0;
}

bool EVPKeyCtxPointer::setRsaImplicitRejection() {
#ifndef OPENSSL_IS_BORINGSSL
  if (!ctx_)
    return false;
  return EVP_PKEY_CTX_ctrl_str(ctx_.get(), "rsa_pkcs1_implicit_rejection", "1") > 0;
  // From the doc -2 means that the option is not supported.
  // The default for the option is enabled and if it has been
  // specifically disabled we want to respect that so we will
  // not throw an error if the option is supported regardless
  // of how it is set. The call to set the value
  // will not affect what is used since a different context is
  // used in the call if the option is supported
#else
  // TODO(jasnell): Boringssl appears not to support this operation.
  // Is there an alternative approach that Boringssl does support?
  return true;
#endif
}

bool EVPKeyCtxPointer::setRsaOaepLabel(DataPointer&& data) {
  if (!ctx_)
    return false;
  if (EVP_PKEY_CTX_set0_rsa_oaep_label(ctx_.get(), static_cast<unsigned char*>(data.get()), data.size()) > 0) {
    // The ctx_ takes ownership of data on success.
    data.release();
    return true;
  }
  return false;
}

bool EVPKeyCtxPointer::setSignatureMd(const EVPMDCtxPointer& md) {
  if (!ctx_)
    return false;
  return EVP_PKEY_CTX_set_signature_md(ctx_.get(), EVP_MD_CTX_get0_md(md.get())) == 1;
}

bool EVPKeyCtxPointer::initForEncrypt() {
  if (!ctx_)
    return false;
  return EVP_PKEY_encrypt_init(ctx_.get()) == 1;
}

bool EVPKeyCtxPointer::initForDecrypt() {
  if (!ctx_)
    return false;
  return EVP_PKEY_decrypt_init(ctx_.get()) == 1;
}

DataPointer EVPKeyCtxPointer::derive() const {
  if (!ctx_)
    return {};
  size_t len = 0;
  if (EVP_PKEY_derive(ctx_.get(), nullptr, &len) != 1)
    return {};
  auto data = DataPointer::Alloc(len);
  if (!data)
    return {};
  if (EVP_PKEY_derive(ctx_.get(), static_cast<unsigned char*>(data.get()), &len) != 1) {
    return {};
  }
  return data;
}

EVPKeyPointer EVPKeyCtxPointer::paramgen() const {
  if (!ctx_)
    return {};
  EVP_PKEY* key = nullptr;
  if (EVP_PKEY_paramgen(ctx_.get(), &key) != 1)
    return {};
  return EVPKeyPointer(key);
}

bool EVPKeyCtxPointer::publicCheck() const {
  if (!ctx_)
    return false;
#ifndef OPENSSL_IS_BORINGSSL
#if OPENSSL_VERSION_MAJOR >= 3
  return EVP_PKEY_public_check_quick(ctx_.get()) == 1;
#else
  return EVP_PKEY_public_check(ctx_.get()) == 1;
#endif
#else // OPENSSL_IS_BORINGSSL
  // Boringssl appears not to support this operation.
  // TODO(jasnell): Is there an alternative approach that Boringssl does
  // support?
  return true;
#endif
}

bool EVPKeyCtxPointer::privateCheck() const {
  if (!ctx_)
    return false;
#ifndef OPENSSL_IS_BORINGSSL
  return EVP_PKEY_check(ctx_.get()) == 1;
#else
  // Boringssl appears not to support this operation.
  // TODO(jasnell): Is there an alternative approach that Boringssl does
  // support?
  return true;
#endif
}

bool EVPKeyCtxPointer::verify(const Buffer<const unsigned char>& sig, const Buffer<const unsigned char>& data) {
  if (!ctx_)
    return false;
  return EVP_PKEY_verify(ctx_.get(), sig.data, sig.len, data.data, data.len) == 1;
}

DataPointer EVPKeyCtxPointer::sign(const Buffer<const unsigned char>& data) {
  if (!ctx_)
    return {};
  size_t len = 0;
  if (EVP_PKEY_sign(ctx_.get(), nullptr, &len, data.data, data.len) != 1) {
    return {};
  }
  auto buf = DataPointer::Alloc(len);
  if (!buf)
    return {};
  if (EVP_PKEY_sign(ctx_.get(), static_cast<unsigned char*>(buf.get()), &len, data.data, data.len) != 1) {
    return {};
  }
  return buf.resize(len);
}

bool EVPKeyCtxPointer::signInto(const Buffer<const unsigned char>& data, Buffer<unsigned char>* sig) {
  if (!ctx_)
    return false;
  size_t len = sig->len;
  if (EVP_PKEY_sign(ctx_.get(), sig->data, &len, data.data, data.len) != 1) {
    return false;
  }
  sig->len = len;
  return true;
}

// ============================================================================

namespace {

  using EVP_PKEY_cipher_init_t = int(EVP_PKEY_CTX* ctx);
  using EVP_PKEY_cipher_t = int(EVP_PKEY_CTX* ctx, unsigned char* out, size_t* outlen, const unsigned char* in, size_t inlen);

  template <EVP_PKEY_cipher_init_t init, EVP_PKEY_cipher_t cipher>
  DataPointer CipherImpl(const EVPKeyPointer& key, const Cipher::CipherParams& params, const Buffer<const void> in) {
    if (!key)
      return {};
    EVPKeyCtxPointer ctx = key.newCtx();
    if (!ctx || init(ctx.get()) <= 0 || !ctx.setRsaPadding(params.padding) ||
        (params.digest != nullptr && !ctx.setRsaOaepMd(params.digest))) {
      return {};
    }

    if (params.label.len != 0 && params.label.data != nullptr && !ctx.setRsaOaepLabel(DataPointer::Copy(params.label))) {
      return {};
    }

    size_t out_len = 0;
    if (cipher(ctx.get(), nullptr, &out_len, static_cast<const unsigned char*>(in.data), in.len) <= 0) {
      return {};
    }

    auto buf = DataPointer::Alloc(out_len);
    if (!buf)
      return {};

    if (cipher(ctx.get(), static_cast<unsigned char*>(buf.get()), &out_len, static_cast<const unsigned char*>(in.data), in.len) <= 0) {
      return {};
    }

    return buf.resize(out_len);
  }
} // namespace

DataPointer Cipher::encrypt(const EVPKeyPointer& key, const CipherParams& params, const Buffer<const void> in) {
  // public operation
  return CipherImpl<EVP_PKEY_encrypt_init, EVP_PKEY_encrypt>(key, params, in);
}

DataPointer Cipher::decrypt(const EVPKeyPointer& key, const CipherParams& params, const Buffer<const void> in) {
  // private operation
  return CipherImpl<EVP_PKEY_decrypt_init, EVP_PKEY_decrypt>(key, params, in);
}

DataPointer Cipher::sign(const EVPKeyPointer& key, const CipherParams& params, const Buffer<const void> in) {
  // private operation
  return CipherImpl<EVP_PKEY_sign_init, EVP_PKEY_sign>(key, params, in);
}

DataPointer Cipher::recover(const EVPKeyPointer& key, const CipherParams& params, const Buffer<const void> in) {
  // public operation
  return CipherImpl<EVP_PKEY_verify_recover_init, EVP_PKEY_verify_recover>(key, params, in);
}

namespace {
  struct CipherCallbackContext {
    Cipher::CipherNameCallback cb;
    void operator()(const char* name) {
      cb(name);
    }
  };

#if OPENSSL_VERSION_MAJOR >= 3
  template <class TypeName, TypeName* fetch_type(OSSL_LIB_CTX*, const char*, const char*), void free_type(TypeName*),
            const TypeName* getbyname(const char*), const char* getname(const TypeName*)>
  void array_push_back(const TypeName*, const char* from, const char*, void* arg) {
    if (from == nullptr)
      return;

    const TypeName* real_instance = getbyname(from);
    if (!real_instance)
      return;

    const char* real_name = getname(real_instance);
    if (!real_name)
      return;

    // EVP_*_fetch() does not support alias names, so we need to pass it the
    // real/original algorithm name.
    // We use EVP_*_fetch() as a filter here because it will only return an
    // instance if the algorithm is supported by the public OpenSSL APIs (some
    // algorithms are used internally by OpenSSL and are also passed to this
    // callback).
    TypeName* fetched = fetch_type(nullptr, real_name, nullptr);
    if (fetched == nullptr)
      return;

    free_type(fetched);
    auto& cb = *(static_cast<CipherCallbackContext*>(arg));
    cb(from);
  }
#else
  template <class TypeName>
  void array_push_back(const TypeName* evp_ref, const char* from, const char* to, void* arg) {
    if (!from)
      return;
    auto& cb = *(static_cast<CipherCallbackContext*>(arg));
    cb(from);
  }
#endif
} // namespace

void Cipher::ForEach(Cipher::CipherNameCallback callback) {
  ClearErrorOnReturn clearErrorOnReturn;
  CipherCallbackContext context;
  context.cb = std::move(callback);

  EVP_CIPHER_do_all_sorted(
#if OPENSSL_VERSION_MAJOR >= 3
      array_push_back<EVP_CIPHER, EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_get_cipherbyname, EVP_CIPHER_get0_name>,
#else
      array_push_back<EVP_CIPHER>,
#endif
      &context);
}

EVPMDCtxPointer::EVPMDCtxPointer() : ctx_(nullptr) {}

EVPMDCtxPointer::EVPMDCtxPointer(EVP_MD_CTX* ctx) : ctx_(ctx) {}

EVPMDCtxPointer::EVPMDCtxPointer(EVPMDCtxPointer&& other) noexcept : ctx_(other.release()) {}

EVPMDCtxPointer& EVPMDCtxPointer::operator=(EVPMDCtxPointer&& other) noexcept {
  ctx_.reset(other.release());
  return *this;
}

EVPMDCtxPointer::~EVPMDCtxPointer() {
  reset();
}

void EVPMDCtxPointer::reset(EVP_MD_CTX* ctx) {
  ctx_.reset(ctx);
}

EVP_MD_CTX* EVPMDCtxPointer::release() {
  return ctx_.release();
}

bool EVPMDCtxPointer::digestInit(const Digest& digest) {
  if (!ctx_)
    return false;
  return EVP_DigestInit_ex(ctx_.get(), digest, nullptr) > 0;
}

bool EVPMDCtxPointer::digestUpdate(const Buffer<const void>& in) {
  if (!ctx_)
    return false;
  return EVP_DigestUpdate(ctx_.get(), in.data, in.len) > 0;
}

DataPointer EVPMDCtxPointer::digestFinal(size_t length) {
  if (!ctx_)
    return {};

  auto buf = DataPointer::Alloc(length);
  if (!buf)
    return {};

  Buffer<void> buffer = buf;

  if (!digestFinalInto(&buffer)) [[unlikely]] {
    return {};
  }

  return buf;
}

bool EVPMDCtxPointer::digestFinalInto(Buffer<void>* buf) {
  if (!ctx_)
    return false;

  auto ptr = static_cast<unsigned char*>(buf->data);

  int ret = (buf->len == getExpectedSize()) ? EVP_DigestFinal_ex(ctx_.get(), ptr, nullptr) : EVP_DigestFinalXOF(ctx_.get(), ptr, buf->len);

  if (ret != 1) [[unlikely]]
    return false;

  return true;
}

size_t EVPMDCtxPointer::getExpectedSize() {
  if (!ctx_)
    return 0;
  return EVP_MD_CTX_size(ctx_.get());
}

size_t EVPMDCtxPointer::getDigestSize() const {
  return EVP_MD_size(getDigest());
}

const EVP_MD* EVPMDCtxPointer::getDigest() const {
  if (!ctx_)
    return nullptr;
  return EVP_MD_CTX_get0_md(ctx_.get());
}

bool EVPMDCtxPointer::hasXofFlag() const {
  if (!ctx_)
    return false;
  return (EVP_MD_flags(getDigest()) & EVP_MD_FLAG_XOF) == EVP_MD_FLAG_XOF;
}

bool EVPMDCtxPointer::copyTo(const EVPMDCtxPointer& other) const {
  if (!ctx_ || !other)
    return {};
  if (EVP_MD_CTX_copy(other.get(), ctx_.get()) != 1)
    return false;
  return true;
}

std::optional<EVP_PKEY_CTX*> EVPMDCtxPointer::signInit(const EVPKeyPointer& key, const Digest& digest) {
  EVP_PKEY_CTX* ctx = nullptr;
  if (!EVP_DigestSignInit(ctx_.get(), &ctx, digest, nullptr, key.get())) {
    return std::nullopt;
  }
  return ctx;
}

std::optional<EVP_PKEY_CTX*> EVPMDCtxPointer::verifyInit(const EVPKeyPointer& key, const Digest& digest) {
  EVP_PKEY_CTX* ctx = nullptr;
  if (!EVP_DigestVerifyInit(ctx_.get(), &ctx, digest, nullptr, key.get())) {
    return std::nullopt;
  }
  return ctx;
}

std::optional<EVP_PKEY_CTX*> EVPMDCtxPointer::signInitWithContext(const EVPKeyPointer& key, const Digest& digest,
                                                                  const Buffer<const unsigned char>& context_string) {
  (void)digest;
#ifdef OSSL_SIGNATURE_PARAM_CONTEXT_STRING
  EVP_PKEY_CTX* ctx = nullptr;

#ifdef OSSL_SIGNATURE_PARAM_INSTANCE
  // Ed25519 requires the INSTANCE param to switch into Ed25519ctx mode.
  // Without it, OpenSSL silently ignores the context string.
  if (key.id() == EVP_PKEY_ED25519) {
    const OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_INSTANCE, const_cast<char*>("Ed25519ctx"), 0),
                                 OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                                                                   const_cast<unsigned char*>(context_string.data), context_string.len),
                                 OSSL_PARAM_END};

    if (!EVP_DigestSignInit_ex(ctx_.get(), &ctx, nullptr, nullptr, nullptr, key.get(), params)) {
      return std::nullopt;
    }
    return ctx;
  }
#endif // OSSL_SIGNATURE_PARAM_INSTANCE

  const OSSL_PARAM params[] = {OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                                                                 const_cast<unsigned char*>(context_string.data), context_string.len),
                               OSSL_PARAM_END};

  if (!EVP_DigestSignInit_ex(ctx_.get(), &ctx, nullptr, nullptr, nullptr, key.get(), params)) {
    return std::nullopt;
  }
  return ctx;
#else
  return std::nullopt;
#endif
}

std::optional<EVP_PKEY_CTX*> EVPMDCtxPointer::verifyInitWithContext(const EVPKeyPointer& key, const Digest& digest,
                                                                    const Buffer<const unsigned char>& context_string) {
  (void)digest;
#ifdef OSSL_SIGNATURE_PARAM_CONTEXT_STRING
  EVP_PKEY_CTX* ctx = nullptr;

#ifdef OSSL_SIGNATURE_PARAM_INSTANCE
  // Ed25519 requires the INSTANCE param to switch into Ed25519ctx mode.
  // Without it, OpenSSL silently ignores the context string.
  if (key.id() == EVP_PKEY_ED25519) {
    const OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_INSTANCE, const_cast<char*>("Ed25519ctx"), 0),
                                 OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                                                                   const_cast<unsigned char*>(context_string.data), context_string.len),
                                 OSSL_PARAM_END};

    if (!EVP_DigestVerifyInit_ex(ctx_.get(), &ctx, nullptr, nullptr, nullptr, key.get(), params)) {
      return std::nullopt;
    }
    return ctx;
  }
#endif // OSSL_SIGNATURE_PARAM_INSTANCE

  const OSSL_PARAM params[] = {OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                                                                 const_cast<unsigned char*>(context_string.data), context_string.len),
                               OSSL_PARAM_END};

  if (!EVP_DigestVerifyInit_ex(ctx_.get(), &ctx, nullptr, nullptr, nullptr, key.get(), params)) {
    return std::nullopt;
  }
  return ctx;
#else
  return std::nullopt;
#endif
}

DataPointer EVPMDCtxPointer::signOneShot(const Buffer<const unsigned char>& buf) const {
  if (!ctx_)
    return {};
  size_t len;
  if (!EVP_DigestSign(ctx_.get(), nullptr, &len, buf.data, buf.len)) {
    return {};
  }
  auto data = DataPointer::Alloc(len);
  if (!data) [[unlikely]]
    return {};

  if (!EVP_DigestSign(ctx_.get(), static_cast<unsigned char*>(data.get()), &len, buf.data, buf.len)) {
    return {};
  }
  return data;
}

DataPointer EVPMDCtxPointer::sign(const Buffer<const unsigned char>& buf) const {
  if (!ctx_) [[unlikely]]
    return {};
  size_t len;
  if (!EVP_DigestSignUpdate(ctx_.get(), buf.data, buf.len) || !EVP_DigestSignFinal(ctx_.get(), nullptr, &len)) {
    return {};
  }
  auto data = DataPointer::Alloc(len);
  if (!data) [[unlikely]]
    return {};
  if (!EVP_DigestSignFinal(ctx_.get(), static_cast<unsigned char*>(data.get()), &len)) {
    return {};
  }
  return data.resize(len);
}

bool EVPMDCtxPointer::verify(const Buffer<const unsigned char>& buf, const Buffer<const unsigned char>& sig) const {
  if (!ctx_)
    return false;
  int ret = EVP_DigestVerify(ctx_.get(), sig.data, sig.len, buf.data, buf.len);
  return ret == 1;
}

EVPMDCtxPointer EVPMDCtxPointer::New() {
  return EVPMDCtxPointer(EVP_MD_CTX_new());
}

// ============================================================================

bool extractP1363(const Buffer<const unsigned char>& buf, unsigned char* dest, size_t n) {
  auto asn1_sig = ECDSASigPointer::Parse(buf);
  if (!asn1_sig)
    return false;

  return BignumPointer::EncodePaddedInto(asn1_sig.r(), dest, n) > 0 && BignumPointer::EncodePaddedInto(asn1_sig.s(), dest + n, n) > 0;
}

#if OPENSSL_VERSION_MAJOR >= 3
EVPMacPointer::EVPMacPointer(EVP_MAC* mac) : mac_(mac) {}

EVPMacPointer::EVPMacPointer(EVPMacPointer&& other) noexcept : mac_(std::move(other.mac_)) {}

EVPMacPointer& EVPMacPointer::operator=(EVPMacPointer&& other) noexcept {
  if (this == &other)
    return *this;
  mac_ = std::move(other.mac_);
  return *this;
}

EVPMacPointer::~EVPMacPointer() {
  mac_.reset();
}

void EVPMacPointer::reset(EVP_MAC* mac) {
  mac_.reset(mac);
}

EVP_MAC* EVPMacPointer::release() {
  return mac_.release();
}

EVPMacPointer EVPMacPointer::Fetch(const char* algorithm) {
  return EVPMacPointer(EVP_MAC_fetch(nullptr, algorithm, nullptr));
}

EVPMacCtxPointer::EVPMacCtxPointer(EVP_MAC_CTX* ctx) : ctx_(ctx) {}

EVPMacCtxPointer::EVPMacCtxPointer(EVPMacCtxPointer&& other) noexcept : ctx_(std::move(other.ctx_)) {}

EVPMacCtxPointer& EVPMacCtxPointer::operator=(EVPMacCtxPointer&& other) noexcept {
  if (this == &other)
    return *this;
  ctx_ = std::move(other.ctx_);
  return *this;
}

EVPMacCtxPointer::~EVPMacCtxPointer() {
  ctx_.reset();
}

void EVPMacCtxPointer::reset(EVP_MAC_CTX* ctx) {
  ctx_.reset(ctx);
}

EVP_MAC_CTX* EVPMacCtxPointer::release() {
  return ctx_.release();
}

bool EVPMacCtxPointer::init(const Buffer<const void>& key, const OSSL_PARAM* params) {
  if (!ctx_)
    return false;
  return EVP_MAC_init(ctx_.get(), static_cast<const unsigned char*>(key.data), key.len, params) == 1;
}

bool EVPMacCtxPointer::update(const Buffer<const void>& data) {
  if (!ctx_)
    return false;
  return EVP_MAC_update(ctx_.get(), static_cast<const unsigned char*>(data.data), data.len) == 1;
}

DataPointer EVPMacCtxPointer::final(size_t length) {
  if (!ctx_)
    return {};
  auto buf = DataPointer::Alloc(length);
  if (!buf)
    return {};

  size_t result_len = length;
  if (EVP_MAC_final(ctx_.get(), static_cast<unsigned char*>(buf.get()), &result_len, length) != 1) {
    return {};
  }

  return buf;
}

EVPMacCtxPointer EVPMacCtxPointer::New(EVP_MAC* mac) {
  if (!mac)
    return EVPMacCtxPointer();
  return EVPMacCtxPointer(EVP_MAC_CTX_new(mac));
}
#endif // OPENSSL_VERSION_MAJOR >= 3

DataPointer hashDigest(const Buffer<const unsigned char>& buf, const EVP_MD* md) {
  if (md == nullptr)
    return {};
  size_t md_len = EVP_MD_size(md);
  unsigned int result_size;
  auto data = DataPointer::Alloc(md_len);
  if (!data)
    return {};

  if (!EVP_Digest(buf.data, buf.len, reinterpret_cast<unsigned char*>(data.get()), &result_size, md, nullptr)) {
    return {};
  }

  return data.resize(result_size);
}

DataPointer xofHashDigest(const Buffer<const unsigned char>& buf, const EVP_MD* md, size_t output_length) {
  if (md == nullptr)
    return {};

  EVPMDCtxPointer ctx = EVPMDCtxPointer::New();
  if (!ctx)
    return {};
  if (ctx.digestInit(md) != 1) {
    return {};
  }
  if (ctx.digestUpdate(reinterpret_cast<const Buffer<const void>&>(buf)) != 1) {
    return {};
  }
  return ctx.digestFinal(output_length);
}

// ============================================================================

size_t Digest::size() const {
  if (md_ == nullptr)
    return 0;
  return EVP_MD_size(md_);
}

const Digest Digest::MD5 = Digest(EVP_md5());
const Digest Digest::SHA1 = Digest(EVP_sha1());
const Digest Digest::SHA256 = Digest(EVP_sha256());
const Digest Digest::SHA384 = Digest(EVP_sha384());
const Digest Digest::SHA512 = Digest(EVP_sha512());

const Digest Digest::FromName(const char* name) {
  return ncrypto::getDigestByName(name);
}

// ============================================================================
// KEM Implementation
#if OPENSSL_VERSION_MAJOR >= 3
#if !OPENSSL_VERSION_PREREQ(3, 5)
bool KEM::SetOperationParameter(EVP_PKEY_CTX* ctx, const EVPKeyPointer& key) {
  const char* operation = nullptr;

  switch (EVP_PKEY_id(key.get())) {
    case EVP_PKEY_RSA:
      operation = OSSL_KEM_PARAM_OPERATION_RSASVE;
      break;
#if OPENSSL_VERSION_PREREQ(3, 2)
    case EVP_PKEY_EC:
    case EVP_PKEY_X25519:
    case EVP_PKEY_X448:
      operation = OSSL_KEM_PARAM_OPERATION_DHKEM;
      break;
#endif
    default:
      unreachable();
  }

  if (operation != nullptr) {
    OSSL_PARAM params[] = {OSSL_PARAM_utf8_string(OSSL_KEM_PARAM_OPERATION, const_cast<char*>(operation), 0), OSSL_PARAM_END};

    if (EVP_PKEY_CTX_set_params(ctx, params) <= 0) {
      return false;
    }
  }

  return true;
}
#endif

std::optional<KEM::EncapsulateResult> KEM::Encapsulate(const EVPKeyPointer& public_key) {
  ClearErrorOnReturn clear_error_on_return;

  auto ctx = public_key.newCtx();
  if (!ctx)
    return std::nullopt;

  if (EVP_PKEY_encapsulate_init(ctx.get(), nullptr) <= 0) {
    return std::nullopt;
  }

#if !OPENSSL_VERSION_PREREQ(3, 5)
  if (!SetOperationParameter(ctx.get(), public_key)) {
    return std::nullopt;
  }
#endif

  // Determine output buffer sizes
  size_t ciphertext_len = 0;
  size_t shared_key_len = 0;

  if (EVP_PKEY_encapsulate(ctx.get(), nullptr, &ciphertext_len, nullptr, &shared_key_len) <= 0) {
    return std::nullopt;
  }

  auto ciphertext = DataPointer::Alloc(ciphertext_len);
  auto shared_key = DataPointer::Alloc(shared_key_len);
  if (!ciphertext || !shared_key)
    return std::nullopt;

  if (EVP_PKEY_encapsulate(ctx.get(), static_cast<unsigned char*>(ciphertext.get()), &ciphertext_len,
                           static_cast<unsigned char*>(shared_key.get()), &shared_key_len) <= 0) {
    return std::nullopt;
  }

  return EncapsulateResult(std::move(ciphertext), std::move(shared_key));
}

DataPointer KEM::Decapsulate(const EVPKeyPointer& private_key, const Buffer<const void>& ciphertext) {
  ClearErrorOnReturn clear_error_on_return;

  auto ctx = private_key.newCtx();
  if (!ctx)
    return {};

  if (EVP_PKEY_decapsulate_init(ctx.get(), nullptr) <= 0) {
    return {};
  }

#if !OPENSSL_VERSION_PREREQ(3, 5)
  if (!SetOperationParameter(ctx.get(), private_key)) {
    return {};
  }
#endif

  // First pass: determine shared secret size
  size_t shared_key_len = 0;
  if (EVP_PKEY_decapsulate(ctx.get(), nullptr, &shared_key_len, static_cast<const unsigned char*>(ciphertext.data), ciphertext.len) <= 0) {
    return {};
  }

  auto shared_key = DataPointer::Alloc(shared_key_len);
  if (!shared_key)
    return {};

  if (EVP_PKEY_decapsulate(ctx.get(), static_cast<unsigned char*>(shared_key.get()), &shared_key_len,
                           static_cast<const unsigned char*>(ciphertext.data), ciphertext.len) <= 0) {
    return {};
  }

  return shared_key;
}

#endif // OPENSSL_VERSION_MAJOR >= 3

} // namespace ncrypto

// ===========================================================================
#if NCRYPTO_BSSL_LIBDECREPIT_MISSING
// While BoringSSL implements EVP_CIPHER_do_all_sorted, it includes this
// inplementation in a library called "libdecrepit", which might not be included
// depending on how boringssl was built. In such cases, a copy of the function
// is provided here:

extern "C" void EVP_CIPHER_do_all_sorted(void (*callback)(const EVP_CIPHER* cipher, const char* name, const char* unused, void* arg),
                                         void* arg) {
  callback(EVP_aes_128_cbc(), "AES-128-CBC", NULL, arg);
  callback(EVP_aes_192_cbc(), "AES-192-CBC", NULL, arg);
  callback(EVP_aes_256_cbc(), "AES-256-CBC", NULL, arg);
  callback(EVP_aes_128_ctr(), "AES-128-CTR", NULL, arg);
  callback(EVP_aes_192_ctr(), "AES-192-CTR", NULL, arg);
  callback(EVP_aes_256_ctr(), "AES-256-CTR", NULL, arg);
  callback(EVP_aes_128_ecb(), "AES-128-ECB", NULL, arg);
  callback(EVP_aes_192_ecb(), "AES-192-ECB", NULL, arg);
  callback(EVP_aes_256_ecb(), "AES-256-ECB", NULL, arg);
  callback(EVP_aes_128_ofb(), "AES-128-OFB", NULL, arg);
  callback(EVP_aes_192_ofb(), "AES-192-OFB", NULL, arg);
  callback(EVP_aes_256_ofb(), "AES-256-OFB", NULL, arg);
  callback(EVP_aes_128_gcm(), "AES-128-GCM", NULL, arg);
  callback(EVP_aes_192_gcm(), "AES-192-GCM", NULL, arg);
  callback(EVP_aes_256_gcm(), "AES-256-GCM", NULL, arg);
  callback(EVP_des_cbc(), "DES-CBC", NULL, arg);
  callback(EVP_des_ecb(), "DES-ECB", NULL, arg);
  callback(EVP_des_ede(), "DES-EDE", NULL, arg);
  callback(EVP_des_ede_cbc(), "DES-EDE-CBC", NULL, arg);
  callback(EVP_des_ede3_cbc(), "DES-EDE3-CBC", NULL, arg);
  callback(EVP_rc2_cbc(), "RC2-CBC", NULL, arg);
  callback(EVP_rc4(), "RC4", NULL, arg);

  // OpenSSL returns everything twice, the second time in lower case.
  callback(EVP_aes_128_cbc(), "aes-128-cbc", NULL, arg);
  callback(EVP_aes_192_cbc(), "aes-192-cbc", NULL, arg);
  callback(EVP_aes_256_cbc(), "aes-256-cbc", NULL, arg);
  callback(EVP_aes_128_ctr(), "aes-128-ctr", NULL, arg);
  callback(EVP_aes_192_ctr(), "aes-192-ctr", NULL, arg);
  callback(EVP_aes_256_ctr(), "aes-256-ctr", NULL, arg);
  callback(EVP_aes_128_ecb(), "aes-128-ecb", NULL, arg);
  callback(EVP_aes_192_ecb(), "aes-192-ecb", NULL, arg);
  callback(EVP_aes_256_ecb(), "aes-256-ecb", NULL, arg);
  callback(EVP_aes_128_ofb(), "aes-128-ofb", NULL, arg);
  callback(EVP_aes_192_ofb(), "aes-192-ofb", NULL, arg);
  callback(EVP_aes_256_ofb(), "aes-256-ofb", NULL, arg);
  callback(EVP_aes_128_gcm(), "aes-128-gcm", NULL, arg);
  callback(EVP_aes_192_gcm(), "aes-192-gcm", NULL, arg);
  callback(EVP_aes_256_gcm(), "aes-256-gcm", NULL, arg);
  callback(EVP_des_cbc(), "des-cbc", NULL, arg);
  callback(EVP_des_ecb(), "des-ecb", NULL, arg);
  callback(EVP_des_ede(), "des-ede", NULL, arg);
  callback(EVP_des_ede_cbc(), "des-ede-cbc", NULL, arg);
  callback(EVP_des_ede3_cbc(), "des-ede3-cbc", NULL, arg);
  callback(EVP_rc2_cbc(), "rc2-cbc", NULL, arg);
  callback(EVP_rc4(), "rc4", NULL, arg);
}
#endif
