#include "HybridMlDsaKeyPair.hpp"

#include <NitroModules/ArrayBuffer.hpp>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "QuickCryptoUtils.hpp"

#if OPENSSL_VERSION_NUMBER >= 0x30500000L
#define RNQC_HAS_ML_DSA 1
#else
#define RNQC_HAS_ML_DSA 0
#endif

namespace margelo::nitro::crypto {

HybridMlDsaKeyPair::~HybridMlDsaKeyPair() {
  if (pkey_ != nullptr) {
    EVP_PKEY_free(pkey_);
    pkey_ = nullptr;
  }
}

int HybridMlDsaKeyPair::getEvpPkeyType() const {
#if RNQC_HAS_ML_DSA
  if (variant_ == "ML-DSA-44")
    return EVP_PKEY_ML_DSA_44;
  if (variant_ == "ML-DSA-65")
    return EVP_PKEY_ML_DSA_65;
  if (variant_ == "ML-DSA-87")
    return EVP_PKEY_ML_DSA_87;
#endif
  return 0;
}

void HybridMlDsaKeyPair::setVariant(const std::string& variant) {
#if !RNQC_HAS_ML_DSA
  throw std::runtime_error("ML-DSA requires OpenSSL 3.5+");
#endif
  if (variant != "ML-DSA-44" && variant != "ML-DSA-65" && variant != "ML-DSA-87") {
    throw std::runtime_error("Invalid ML-DSA variant: " + variant + ". Must be ML-DSA-44, ML-DSA-65, or ML-DSA-87");
  }
  variant_ = variant;
}

std::shared_ptr<Promise<void>> HybridMlDsaKeyPair::generateKeyPair(double publicFormat, double publicType, double privateFormat,
                                                                   double privateType) {
  return Promise<void>::async([this, publicFormat, publicType, privateFormat, privateType]() {
    this->generateKeyPairSync(publicFormat, publicType, privateFormat, privateType);
  });
}

void HybridMlDsaKeyPair::generateKeyPairSync(double publicFormat, double publicType, double privateFormat, double privateType) {
#if !RNQC_HAS_ML_DSA
  throw std::runtime_error("ML-DSA requires OpenSSL 3.5+");
#else
  clearOpenSSLErrors();

  if (variant_.empty()) {
    throw std::runtime_error("ML-DSA variant not set. Call setVariant() first.");
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
    throw std::runtime_error("Failed to generate ML-DSA key pair: " + getOpenSSLError());
  }

  EVP_PKEY_CTX_free(pctx);
#endif
}

std::shared_ptr<ArrayBuffer> HybridMlDsaKeyPair::getPublicKey() {
#if !RNQC_HAS_ML_DSA
  throw std::runtime_error("ML-DSA requires OpenSSL 3.5+");
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

std::shared_ptr<ArrayBuffer> HybridMlDsaKeyPair::getPrivateKey() {
#if !RNQC_HAS_ML_DSA
  throw std::runtime_error("ML-DSA requires OpenSSL 3.5+");
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
    // Use PKCS8 format for DER export (not raw private key format)
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

std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>> HybridMlDsaKeyPair::sign(const std::shared_ptr<ArrayBuffer>& message) {
  auto nativeMessage = ToNativeArrayBuffer(message);
  return Promise<std::shared_ptr<ArrayBuffer>>::async([this, nativeMessage]() { return this->signSync(nativeMessage); });
}

std::shared_ptr<ArrayBuffer> HybridMlDsaKeyPair::signSync(const std::shared_ptr<ArrayBuffer>& message) {
#if !RNQC_HAS_ML_DSA
  throw std::runtime_error("ML-DSA requires OpenSSL 3.5+");
#else
  clearOpenSSLErrors();
  checkKeyPair();

  EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
  if (md_ctx == nullptr) {
    throw std::runtime_error("Failed to create signing context");
  }

  EVP_PKEY_CTX* pkey_ctx = EVP_PKEY_CTX_new_from_name(nullptr, variant_.c_str(), nullptr);
  if (pkey_ctx == nullptr) {
    EVP_MD_CTX_free(md_ctx);
    throw std::runtime_error("Failed to create signing context for " + variant_);
  }

  if (EVP_DigestSignInit(md_ctx, &pkey_ctx, nullptr, nullptr, pkey_) <= 0) {
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_CTX_free(pkey_ctx);
    throw std::runtime_error("Failed to initialize signing: " + getOpenSSLError());
  }

  size_t sig_len = 0;
  if (EVP_DigestSign(md_ctx, nullptr, &sig_len, message->data(), message->size()) <= 0) {
    EVP_MD_CTX_free(md_ctx);
    throw std::runtime_error("Failed to calculate signature size: " + getOpenSSLError());
  }

  uint8_t* sig = new uint8_t[sig_len];

  if (EVP_DigestSign(md_ctx, sig, &sig_len, message->data(), message->size()) <= 0) {
    EVP_MD_CTX_free(md_ctx);
    delete[] sig;
    throw std::runtime_error("Failed to sign message: " + getOpenSSLError());
  }

  EVP_MD_CTX_free(md_ctx);

  return std::make_shared<NativeArrayBuffer>(sig, sig_len, [=]() { delete[] sig; });
#endif
}

std::shared_ptr<Promise<bool>> HybridMlDsaKeyPair::verify(const std::shared_ptr<ArrayBuffer>& signature,
                                                          const std::shared_ptr<ArrayBuffer>& message) {
  auto nativeSignature = ToNativeArrayBuffer(signature);
  auto nativeMessage = ToNativeArrayBuffer(message);
  return Promise<bool>::async([this, nativeSignature, nativeMessage]() { return this->verifySync(nativeSignature, nativeMessage); });
}

bool HybridMlDsaKeyPair::verifySync(const std::shared_ptr<ArrayBuffer>& signature, const std::shared_ptr<ArrayBuffer>& message) {
#if !RNQC_HAS_ML_DSA
  throw std::runtime_error("ML-DSA requires OpenSSL 3.5+");
#else
  clearOpenSSLErrors();
  checkKeyPair();

  EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
  if (md_ctx == nullptr) {
    throw std::runtime_error("Failed to create verify context");
  }

  EVP_PKEY_CTX* pkey_ctx = EVP_PKEY_CTX_new_from_name(nullptr, variant_.c_str(), nullptr);
  if (pkey_ctx == nullptr) {
    EVP_MD_CTX_free(md_ctx);
    throw std::runtime_error("Failed to create verify context for " + variant_);
  }

  if (EVP_DigestVerifyInit(md_ctx, &pkey_ctx, nullptr, nullptr, pkey_) <= 0) {
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_CTX_free(pkey_ctx);
    throw std::runtime_error("Failed to initialize verification: " + getOpenSSLError());
  }

  int result = EVP_DigestVerify(md_ctx, signature->data(), signature->size(), message->data(), message->size());

  EVP_MD_CTX_free(md_ctx);

  if (result < 0) {
    throw std::runtime_error("Verification error: " + getOpenSSLError());
  }

  return result == 1;
#endif
}

void HybridMlDsaKeyPair::checkKeyPair() {
  if (pkey_ == nullptr) {
    throw std::runtime_error("Key pair not initialized");
  }
}

} // namespace margelo::nitro::crypto
