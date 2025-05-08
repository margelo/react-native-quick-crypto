#include <memory>
#include <string>

#include "HybridEdKeyPair.hpp"

namespace margelo::nitro::crypto {

std::shared_ptr<Promise<void>> HybridEdKeyPair::generateKeyPair(double publicFormat, double publicType, double privateFormat,
                                                                double privateType, const std::optional<std::string>& cipher,
                                                                const std::optional<std::shared_ptr<ArrayBuffer>>& passphrase) {
  // get owned NativeArrayBuffers before passing to sync function
  std::optional<std::shared_ptr<ArrayBuffer>> nativePassphrase = std::nullopt;
  if (passphrase.has_value()) {
    nativePassphrase = ToNativeArrayBuffer(passphrase.value());
  }

  return Promise<void>::async([this, publicFormat, publicType, privateFormat, privateType, cipher, nativePassphrase]() {
    this->generateKeyPairSync(publicFormat, publicType, privateFormat, privateType, cipher, nativePassphrase);
  });
}

void HybridEdKeyPair::generateKeyPairSync(double publicFormat, double publicType, double privateFormat, double privateType,
                                          const std::optional<std::string>& cipher,
                                          const std::optional<std::shared_ptr<ArrayBuffer>>& passphrase) {
  EVP_PKEY_CTX* pctx;

  // key context
  pctx = EVP_PKEY_CTX_new_from_name(nullptr, this->curve.c_str(), nullptr);
  if (pctx == nullptr) {
    throw std::runtime_error("Invalid curve name: " + this->curve);
  }

  // keygen init
  if (EVP_PKEY_keygen_init(pctx) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    throw std::runtime_error("Failed to initialize keygen");
  }

  // generate key
  EVP_PKEY_keygen(pctx, &this->pkey);
  if (this->pkey == nullptr) {
    EVP_PKEY_CTX_free(pctx);
    throw std::runtime_error("Failed to generate key");
  }

  // cleanup
  EVP_PKEY_CTX_free(pctx);
}

std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>> HybridEdKeyPair::sign(const std::shared_ptr<ArrayBuffer>& message,
                                                                             const std::optional<std::shared_ptr<ArrayBuffer>>& key) {
  // get owned NativeArrayBuffer before passing to sync function
  auto nativeMessage = ToNativeArrayBuffer(message);
  std::optional<std::shared_ptr<ArrayBuffer>> nativeKey = std::nullopt;
  if (key.has_value()) {
    nativeKey = ToNativeArrayBuffer(key.value());
  }

  return Promise<std::shared_ptr<ArrayBuffer>>::async(
      [this, nativeMessage, nativeKey]() { return this->signSync(nativeMessage, nativeKey); });
}

std::shared_ptr<ArrayBuffer> HybridEdKeyPair::signSync(const std::shared_ptr<ArrayBuffer>& message,
                                                       const std::optional<std::shared_ptr<ArrayBuffer>>& key) {

  size_t sig_len = 0;
  uint8_t* sig = NULL;
  EVP_MD_CTX* md_ctx = nullptr;
  EVP_PKEY_CTX* pkey_ctx = nullptr;

  // get key to use for signing
  EVP_PKEY* pkey = this->importPrivateKey(key);

  // key context
  md_ctx = EVP_MD_CTX_new();
  if (md_ctx == nullptr) {
    EVP_MD_CTX_free(md_ctx);
    throw std::runtime_error("Error creating signing context");
  }

  pkey_ctx = EVP_PKEY_CTX_new_from_name(nullptr, this->curve.c_str(), nullptr);
  if (pkey_ctx == nullptr) {
    EVP_PKEY_CTX_free(pkey_ctx);
    throw std::runtime_error("Error creating signing context: " + this->curve);
  }

  if (EVP_DigestSignInit(md_ctx, &pkey_ctx, NULL, NULL, pkey) <= 0) {
    EVP_MD_CTX_free(md_ctx);
    char* err = ERR_error_string(ERR_get_error(), NULL);
    throw std::runtime_error("Failed to initialize signing: " + std::string(err));
  }

  // Calculate the required size for the signature by passing a NULL buffer.
  if (EVP_DigestSign(md_ctx, NULL, &sig_len, message.get()->data(), message.get()->size()) <= 0) {
    EVP_MD_CTX_free(md_ctx);
    throw std::runtime_error("Failed to calculate signature size");
  }
  sig = new uint8_t[sig_len];

  // Actually calculate the signature
  if (EVP_DigestSign(md_ctx, sig, &sig_len, message.get()->data(), message.get()->size()) <= 0) {
    EVP_MD_CTX_free(md_ctx);
    throw std::runtime_error("Failed to calculate signature");
  }

  // return value for JS
  std::shared_ptr<ArrayBuffer> signature = std::make_shared<NativeArrayBuffer>(sig, sig_len, [=]() { delete[] sig; });

  // Clean up
  EVP_MD_CTX_free(md_ctx);

  return signature;
}

std::shared_ptr<Promise<bool>> HybridEdKeyPair::verify(const std::shared_ptr<ArrayBuffer>& signature,
                                                       const std::shared_ptr<ArrayBuffer>& message,
                                                       const std::optional<std::shared_ptr<ArrayBuffer>>& key) {
  // get owned NativeArrayBuffers before passing to sync function
  auto nativeSignature = ToNativeArrayBuffer(signature);
  auto nativeMessage = ToNativeArrayBuffer(message);
  std::optional<std::shared_ptr<ArrayBuffer>> nativeKey = std::nullopt;
  if (key.has_value()) {
    nativeKey = ToNativeArrayBuffer(key.value());
  }

  return Promise<bool>::async(
      [this, nativeSignature, nativeMessage, nativeKey]() { return this->verifySync(nativeSignature, nativeMessage, nativeKey); });
}

bool HybridEdKeyPair::verifySync(const std::shared_ptr<ArrayBuffer>& signature, const std::shared_ptr<ArrayBuffer>& message,
                                 const std::optional<std::shared_ptr<ArrayBuffer>>& key) {
  // get key to use for verifying
  EVP_PKEY* pkey = this->importPublicKey(key);

  EVP_MD_CTX* md_ctx = nullptr;
  EVP_PKEY_CTX* pkey_ctx = nullptr;

  // key context
  md_ctx = EVP_MD_CTX_new();
  if (md_ctx == nullptr) {
    EVP_MD_CTX_free(md_ctx);
    throw std::runtime_error("Error creating verify context");
  }

  pkey_ctx = EVP_PKEY_CTX_new_from_name(nullptr, this->curve.c_str(), nullptr);
  if (pkey_ctx == nullptr) {
    EVP_PKEY_CTX_free(pkey_ctx);
    throw std::runtime_error("Error creating verify context: " + this->curve);
  }

  if (EVP_DigestVerifyInit(md_ctx, &pkey_ctx, NULL, NULL, pkey) <= 0) {
    EVP_MD_CTX_free(md_ctx);
    char* err = ERR_error_string(ERR_get_error(), NULL);
    throw std::runtime_error("Failed to initialize verify: " + std::string(err));
  }

  // verify
  auto res = EVP_DigestVerify(md_ctx, signature.get()->data(), signature.get()->size(), message.get()->data(), message.get()->size());

  // return value for JS
  if (res < 0) {
    EVP_MD_CTX_free(md_ctx);
    throw std::runtime_error("Failed to verify");
  }
  return res == 1; // true if 1, false if 0
}

std::shared_ptr<ArrayBuffer> HybridEdKeyPair::getPublicKey() {
  this->checkKeyPair();
  size_t len = 32;
  uint8_t* publ = new uint8_t[len];
  EVP_PKEY_get_raw_public_key(this->pkey, publ, &len);

  return std::make_shared<NativeArrayBuffer>(publ, len, [=]() { delete[] publ; });
}

std::shared_ptr<ArrayBuffer> HybridEdKeyPair::getPrivateKey() {
  this->checkKeyPair();
  size_t len = 32;
  uint8_t* priv = new uint8_t[len];
  EVP_PKEY_get_raw_private_key(this->pkey, priv, &len);

  return std::make_shared<NativeArrayBuffer>(priv, len, [=]() { delete[] priv; });
}

void HybridEdKeyPair::checkKeyPair() {
  if (this->pkey == nullptr) {
    throw std::runtime_error("Keypair not initialized");
  }
}

void HybridEdKeyPair::setCurve(const std::string& curve) {
  this->curve = curve;
}

EVP_PKEY* HybridEdKeyPair::importPublicKey(const std::optional<std::shared_ptr<ArrayBuffer>>& key) {
  EVP_PKEY* pkey = nullptr;
  if (key.has_value()) {
    pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, // TODO: use this->curve somehow
                                       NULL, key.value()->data(), 32);
    if (pkey == nullptr) {
      throw std::runtime_error("Failed to read public key");
    }
  } else {
    this->checkKeyPair();
    pkey = this->pkey;
  }
  return pkey;
}

EVP_PKEY* HybridEdKeyPair::importPrivateKey(const std::optional<std::shared_ptr<ArrayBuffer>>& key) {
  EVP_PKEY* pkey = nullptr;
  if (key.has_value()) {
    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, // TODO: use this->curve somehow
                                        NULL, key.value()->data(), 32);
    if (pkey == nullptr) {
      throw std::runtime_error("Failed to read private key");
    }
  } else {
    this->checkKeyPair();
    pkey = this->pkey;
  }
  return pkey;
}

} // namespace margelo::nitro::crypto
