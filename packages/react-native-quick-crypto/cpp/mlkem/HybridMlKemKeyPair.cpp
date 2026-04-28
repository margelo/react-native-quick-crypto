#include "HybridMlKemKeyPair.hpp"

#include <NitroModules/ArrayBuffer.hpp>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "QuickCryptoUtils.hpp"

#if OPENSSL_VERSION_NUMBER >= 0x30500000L
#define RNQC_HAS_ML_KEM 1
#else
#define RNQC_HAS_ML_KEM 0
#endif

namespace margelo::nitro::crypto {

using EVP_PKEY_CTX_ptr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

void HybridMlKemKeyPair::setVariant(const std::string& variant) {
#if !RNQC_HAS_ML_KEM
  throw std::runtime_error("ML-KEM requires OpenSSL 3.5+");
#endif
  if (variant != "ML-KEM-512" && variant != "ML-KEM-768" && variant != "ML-KEM-1024") {
    throw std::runtime_error("Invalid ML-KEM variant: " + variant + ". Must be ML-KEM-512, ML-KEM-768, or ML-KEM-1024");
  }
  variant_ = variant;
}

std::shared_ptr<Promise<void>> HybridMlKemKeyPair::generateKeyPair(double publicFormat, double publicType, double privateFormat,
                                                                   double privateType) {
  auto self = this->shared_cast<HybridMlKemKeyPair>();
  return Promise<void>::async([self, publicFormat, publicType, privateFormat, privateType]() {
    self->generateKeyPairSync(publicFormat, publicType, privateFormat, privateType);
  });
}

void HybridMlKemKeyPair::generateKeyPairSync(double publicFormat, double publicType, double privateFormat, double privateType) {
#if !RNQC_HAS_ML_KEM
  throw std::runtime_error("ML-KEM requires OpenSSL 3.5+");
#else
  clearOpenSSLErrors();

  if (variant_.empty()) {
    throw std::runtime_error("ML-KEM variant not set. Call setVariant() first.");
  }

  publicFormat_ = static_cast<int>(publicFormat);
  publicType_ = static_cast<int>(publicType);
  privateFormat_ = static_cast<int>(privateFormat);
  privateType_ = static_cast<int>(privateType);

  pkey_.reset();

  EVP_PKEY_CTX_ptr pctx(EVP_PKEY_CTX_new_from_name(nullptr, variant_.c_str(), nullptr), EVP_PKEY_CTX_free);
  if (pctx == nullptr) {
    throw std::runtime_error("Failed to create key context for " + variant_ + ": " + getOpenSSLError());
  }

  if (EVP_PKEY_keygen_init(pctx.get()) <= 0) {
    throw std::runtime_error("Failed to initialize keygen: " + getOpenSSLError());
  }

  EVP_PKEY* raw = nullptr;
  if (EVP_PKEY_keygen(pctx.get(), &raw) <= 0) {
    throw std::runtime_error("Failed to generate ML-KEM key pair: " + getOpenSSLError());
  }

  pkey_.reset(raw);
#endif
}

std::shared_ptr<ArrayBuffer> HybridMlKemKeyPair::getPublicKey() {
#if !RNQC_HAS_ML_KEM
  throw std::runtime_error("ML-KEM requires OpenSSL 3.5+");
#else
  checkKeyPair();

  BIO* bio = BIO_new(BIO_s_mem());
  if (!bio) {
    throw std::runtime_error("Failed to create BIO for public key export");
  }

  int result;
  if (publicFormat_ == 1) {
    result = PEM_write_bio_PUBKEY(bio, pkey_.get());
  } else {
    result = i2d_PUBKEY_bio(bio, pkey_.get());
  }

  if (result != 1) {
    BIO_free(bio);
    throw std::runtime_error("Failed to export public key: " + getOpenSSLError());
  }

  BUF_MEM* bptr;
  BIO_get_mem_ptr(bio, &bptr);

  size_t len = bptr->length;
  auto buf = std::make_unique<uint8_t[]>(len);
  memcpy(buf.get(), bptr->data, len);

  BIO_free(bio);

  uint8_t* raw_ptr = buf.get();
  return std::make_shared<NativeArrayBuffer>(buf.release(), len, [raw_ptr]() { delete[] raw_ptr; });
#endif
}

std::shared_ptr<ArrayBuffer> HybridMlKemKeyPair::getPrivateKey() {
#if !RNQC_HAS_ML_KEM
  throw std::runtime_error("ML-KEM requires OpenSSL 3.5+");
#else
  checkKeyPair();

  BIO* bio = BIO_new(BIO_s_mem());
  if (!bio) {
    throw std::runtime_error("Failed to create BIO for private key export");
  }

  int result;
  if (privateFormat_ == 1) {
    result = PEM_write_bio_PrivateKey(bio, pkey_.get(), nullptr, nullptr, 0, nullptr, nullptr);
  } else {
    result = i2d_PKCS8PrivateKey_bio(bio, pkey_.get(), nullptr, nullptr, 0, nullptr, nullptr);
  }

  if (result != 1) {
    BIO_free(bio);
    throw std::runtime_error("Failed to export private key: " + getOpenSSLError());
  }

  BUF_MEM* bptr;
  BIO_get_mem_ptr(bio, &bptr);

  size_t len = bptr->length;
  auto buf = std::make_unique<uint8_t[]>(len);
  memcpy(buf.get(), bptr->data, len);

  // Wipe the private key bytes from the BIO before freeing.
  secureZero(bptr->data, bptr->length);
  BIO_free(bio);

  uint8_t* raw_ptr = buf.get();
  return std::make_shared<NativeArrayBuffer>(buf.release(), len, [raw_ptr]() { delete[] raw_ptr; });
#endif
}

void HybridMlKemKeyPair::setPublicKey(const std::shared_ptr<ArrayBuffer>& keyData, double format, double type) {
#if !RNQC_HAS_ML_KEM
  throw std::runtime_error("ML-KEM requires OpenSSL 3.5+");
#else
  clearOpenSSLErrors();

  if (variant_.empty()) {
    throw std::runtime_error("ML-KEM variant not set. Call setVariant() first.");
  }

  publicFormat_ = static_cast<int>(format);
  publicType_ = static_cast<int>(type);

  BIO* bio = BIO_new_mem_buf(keyData->data(), static_cast<int>(keyData->size()));
  if (!bio) {
    throw std::runtime_error("Failed to create BIO for public key import");
  }

  EVP_PKEY* importedKey = nullptr;
  if (publicFormat_ == 1) {
    importedKey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
  } else {
    importedKey = d2i_PUBKEY_bio(bio, nullptr);
  }

  BIO_free(bio);

  if (importedKey == nullptr) {
    throw std::runtime_error("Failed to import public key: " + getOpenSSLError());
  }

  pkey_.reset(importedKey);
#endif
}

void HybridMlKemKeyPair::setPrivateKey(const std::shared_ptr<ArrayBuffer>& keyData, double format, double type) {
#if !RNQC_HAS_ML_KEM
  throw std::runtime_error("ML-KEM requires OpenSSL 3.5+");
#else
  clearOpenSSLErrors();

  if (variant_.empty()) {
    throw std::runtime_error("ML-KEM variant not set. Call setVariant() first.");
  }

  privateFormat_ = static_cast<int>(format);
  privateType_ = static_cast<int>(type);

  BIO* bio = BIO_new_mem_buf(keyData->data(), static_cast<int>(keyData->size()));
  if (!bio) {
    throw std::runtime_error("Failed to create BIO for private key import");
  }

  EVP_PKEY* importedKey = nullptr;
  if (privateFormat_ == 1) {
    importedKey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
  } else {
    importedKey = d2i_PrivateKey_bio(bio, nullptr);
  }

  BIO_free(bio);

  if (importedKey == nullptr) {
    throw std::runtime_error("Failed to import private key: " + getOpenSSLError());
  }

  pkey_.reset(importedKey);
#endif
}

std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>> HybridMlKemKeyPair::encapsulate() {
  auto self = this->shared_cast<HybridMlKemKeyPair>();
  return Promise<std::shared_ptr<ArrayBuffer>>::async([self]() { return self->encapsulateSync(); });
}

std::shared_ptr<ArrayBuffer> HybridMlKemKeyPair::encapsulateSync() {
#if !RNQC_HAS_ML_KEM
  throw std::runtime_error("ML-KEM requires OpenSSL 3.5+");
#else
  clearOpenSSLErrors();
  checkKeyPair();

  EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new(pkey_.get(), nullptr), EVP_PKEY_CTX_free);
  if (ctx == nullptr) {
    throw std::runtime_error("Failed to create encapsulation context: " + getOpenSSLError());
  }

  if (EVP_PKEY_encapsulate_init(ctx.get(), nullptr) <= 0) {
    throw std::runtime_error("Failed to initialize encapsulation: " + getOpenSSLError());
  }

  size_t ct_len = 0;
  size_t sk_len = 0;
  if (EVP_PKEY_encapsulate(ctx.get(), nullptr, &ct_len, nullptr, &sk_len) <= 0) {
    throw std::runtime_error("Failed to determine encapsulation output sizes: " + getOpenSSLError());
  }

  // Pack result as: [uint32 ct_len][uint32 sk_len][ciphertext][shared_key]
  size_t header_size = sizeof(uint32_t) * 2;
  size_t total_size = header_size + ct_len + sk_len;
  auto out = std::make_unique<uint8_t[]>(total_size);

  uint32_t ct_len_u32 = static_cast<uint32_t>(ct_len);
  uint32_t sk_len_u32 = static_cast<uint32_t>(sk_len);
  memcpy(out.get(), &ct_len_u32, sizeof(uint32_t));
  memcpy(out.get() + sizeof(uint32_t), &sk_len_u32, sizeof(uint32_t));

  uint8_t* ct_data = out.get() + header_size;
  uint8_t* sk_data = ct_data + ct_len;

  if (EVP_PKEY_encapsulate(ctx.get(), ct_data, &ct_len, sk_data, &sk_len) <= 0) {
    throw std::runtime_error("Failed to encapsulate: " + getOpenSSLError());
  }

  uint8_t* raw_ptr = out.get();
  return std::make_shared<NativeArrayBuffer>(out.release(), total_size, [raw_ptr]() { delete[] raw_ptr; });
#endif
}

std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>> HybridMlKemKeyPair::decapsulate(const std::shared_ptr<ArrayBuffer>& ciphertext) {
  auto nativeCiphertext = ToNativeArrayBuffer(ciphertext);
  auto self = this->shared_cast<HybridMlKemKeyPair>();
  return Promise<std::shared_ptr<ArrayBuffer>>::async([self, nativeCiphertext]() { return self->decapsulateSync(nativeCiphertext); });
}

std::shared_ptr<ArrayBuffer> HybridMlKemKeyPair::decapsulateSync(const std::shared_ptr<ArrayBuffer>& ciphertext) {
#if !RNQC_HAS_ML_KEM
  throw std::runtime_error("ML-KEM requires OpenSSL 3.5+");
#else
  clearOpenSSLErrors();
  checkKeyPair();

  EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new(pkey_.get(), nullptr), EVP_PKEY_CTX_free);
  if (ctx == nullptr) {
    throw std::runtime_error("Failed to create decapsulation context: " + getOpenSSLError());
  }

  if (EVP_PKEY_decapsulate_init(ctx.get(), nullptr) <= 0) {
    throw std::runtime_error("Failed to initialize decapsulation: " + getOpenSSLError());
  }

  const uint8_t* ct_data = ciphertext->data();
  size_t ct_size = ciphertext->size();

  size_t sk_len = 0;
  if (EVP_PKEY_decapsulate(ctx.get(), nullptr, &sk_len, ct_data, ct_size) <= 0) {
    throw std::runtime_error("Failed to determine shared key size: " + getOpenSSLError());
  }

  auto sk_buf = std::make_unique<uint8_t[]>(sk_len);

  if (EVP_PKEY_decapsulate(ctx.get(), sk_buf.get(), &sk_len, ct_data, ct_size) <= 0) {
    throw std::runtime_error("Failed to decapsulate: " + getOpenSSLError());
  }

  uint8_t* raw_ptr = sk_buf.get();
  return std::make_shared<NativeArrayBuffer>(sk_buf.release(), sk_len, [raw_ptr]() { delete[] raw_ptr; });
#endif
}

void HybridMlKemKeyPair::checkKeyPair() {
  if (!pkey_) {
    throw std::runtime_error("Key pair not initialized");
  }
}

} // namespace margelo::nitro::crypto
