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

HybridMlKemKeyPair::~HybridMlKemKeyPair() {
  if (pkey_ != nullptr) {
    EVP_PKEY_free(pkey_);
    pkey_ = nullptr;
  }
}

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
  return Promise<void>::async([this, publicFormat, publicType, privateFormat, privateType]() {
    this->generateKeyPairSync(publicFormat, publicType, privateFormat, privateType);
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

  if (pkey_ != nullptr) {
    EVP_PKEY_free(pkey_);
    pkey_ = nullptr;
  }

  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(nullptr, variant_.c_str(), nullptr);
  if (pctx == nullptr) {
    throw std::runtime_error("Failed to create key context for " + variant_ + ": " + getOpenSSLError());
  }

  if (EVP_PKEY_keygen_init(pctx) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    throw std::runtime_error("Failed to initialize keygen: " + getOpenSSLError());
  }

  if (EVP_PKEY_keygen(pctx, &pkey_) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    throw std::runtime_error("Failed to generate ML-KEM key pair: " + getOpenSSLError());
  }

  EVP_PKEY_CTX_free(pctx);
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
    result = PEM_write_bio_PUBKEY(bio, pkey_);
  } else {
    result = i2d_PUBKEY_bio(bio, pkey_);
  }

  if (result != 1) {
    BIO_free(bio);
    throw std::runtime_error("Failed to export public key: " + getOpenSSLError());
  }

  BUF_MEM* bptr;
  BIO_get_mem_ptr(bio, &bptr);

  uint8_t* data = new uint8_t[bptr->length];
  memcpy(data, bptr->data, bptr->length);
  size_t len = bptr->length;

  BIO_free(bio);

  return std::make_shared<NativeArrayBuffer>(data, len, [=]() { delete[] data; });
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
    result = PEM_write_bio_PrivateKey(bio, pkey_, nullptr, nullptr, 0, nullptr, nullptr);
  } else {
    result = i2d_PKCS8PrivateKey_bio(bio, pkey_, nullptr, nullptr, 0, nullptr, nullptr);
  }

  if (result != 1) {
    BIO_free(bio);
    throw std::runtime_error("Failed to export private key: " + getOpenSSLError());
  }

  BUF_MEM* bptr;
  BIO_get_mem_ptr(bio, &bptr);

  uint8_t* data = new uint8_t[bptr->length];
  memcpy(data, bptr->data, bptr->length);
  size_t len = bptr->length;

  BIO_free(bio);

  return std::make_shared<NativeArrayBuffer>(data, len, [=]() { delete[] data; });
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

  if (pkey_ != nullptr) {
    EVP_PKEY_free(pkey_);
  }
  pkey_ = importedKey;
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

  if (pkey_ != nullptr) {
    EVP_PKEY_free(pkey_);
  }
  pkey_ = importedKey;
#endif
}

std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>> HybridMlKemKeyPair::encapsulate() {
  return Promise<std::shared_ptr<ArrayBuffer>>::async([this]() { return this->encapsulateSync(); });
}

std::shared_ptr<ArrayBuffer> HybridMlKemKeyPair::encapsulateSync() {
#if !RNQC_HAS_ML_KEM
  throw std::runtime_error("ML-KEM requires OpenSSL 3.5+");
#else
  clearOpenSSLErrors();
  checkKeyPair();

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey_, nullptr);
  if (ctx == nullptr) {
    throw std::runtime_error("Failed to create encapsulation context: " + getOpenSSLError());
  }

  if (EVP_PKEY_encapsulate_init(ctx, nullptr) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("Failed to initialize encapsulation: " + getOpenSSLError());
  }

  size_t ct_len = 0;
  size_t sk_len = 0;
  if (EVP_PKEY_encapsulate(ctx, nullptr, &ct_len, nullptr, &sk_len) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("Failed to determine encapsulation output sizes: " + getOpenSSLError());
  }

  // Pack result as: [uint32 ct_len][uint32 sk_len][ciphertext][shared_key]
  size_t header_size = sizeof(uint32_t) * 2;
  size_t total_size = header_size + ct_len + sk_len;
  uint8_t* out = new uint8_t[total_size];

  uint32_t ct_len_u32 = static_cast<uint32_t>(ct_len);
  uint32_t sk_len_u32 = static_cast<uint32_t>(sk_len);
  memcpy(out, &ct_len_u32, sizeof(uint32_t));
  memcpy(out + sizeof(uint32_t), &sk_len_u32, sizeof(uint32_t));

  uint8_t* ct_data = out + header_size;
  uint8_t* sk_data = ct_data + ct_len;

  if (EVP_PKEY_encapsulate(ctx, ct_data, &ct_len, sk_data, &sk_len) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    delete[] out;
    throw std::runtime_error("Failed to encapsulate: " + getOpenSSLError());
  }

  EVP_PKEY_CTX_free(ctx);

  return std::make_shared<NativeArrayBuffer>(out, total_size, [=]() { delete[] out; });
#endif
}

std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>> HybridMlKemKeyPair::decapsulate(const std::shared_ptr<ArrayBuffer>& ciphertext) {
  auto nativeCiphertext = ToNativeArrayBuffer(ciphertext);
  return Promise<std::shared_ptr<ArrayBuffer>>::async([this, nativeCiphertext]() { return this->decapsulateSync(nativeCiphertext); });
}

std::shared_ptr<ArrayBuffer> HybridMlKemKeyPair::decapsulateSync(const std::shared_ptr<ArrayBuffer>& ciphertext) {
#if !RNQC_HAS_ML_KEM
  throw std::runtime_error("ML-KEM requires OpenSSL 3.5+");
#else
  clearOpenSSLErrors();
  checkKeyPair();

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey_, nullptr);
  if (ctx == nullptr) {
    throw std::runtime_error("Failed to create decapsulation context: " + getOpenSSLError());
  }

  if (EVP_PKEY_decapsulate_init(ctx, nullptr) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("Failed to initialize decapsulation: " + getOpenSSLError());
  }

  const uint8_t* ct_data = ciphertext->data();
  size_t ct_size = ciphertext->size();

  size_t sk_len = 0;
  if (EVP_PKEY_decapsulate(ctx, nullptr, &sk_len, ct_data, ct_size) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("Failed to determine shared key size: " + getOpenSSLError());
  }

  uint8_t* sk_data = new uint8_t[sk_len];

  if (EVP_PKEY_decapsulate(ctx, sk_data, &sk_len, ct_data, ct_size) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    delete[] sk_data;
    throw std::runtime_error("Failed to decapsulate: " + getOpenSSLError());
  }

  EVP_PKEY_CTX_free(ctx);

  return std::make_shared<NativeArrayBuffer>(sk_data, sk_len, [=]() { delete[] sk_data; });
#endif
}

void HybridMlKemKeyPair::checkKeyPair() {
  if (pkey_ == nullptr) {
    throw std::runtime_error("Key pair not initialized");
  }
}

} // namespace margelo::nitro::crypto
