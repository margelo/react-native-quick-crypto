#include <NitroModules/ArrayBuffer.hpp>
#include <memory>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string>

#include "HybridEdKeyPair.hpp"

namespace margelo::nitro::crypto {

std::shared_ptr<ArrayBuffer> HybridEdKeyPair::diffieHellman(const std::shared_ptr<ArrayBuffer>& privateKey,
                                                            const std::shared_ptr<ArrayBuffer>& publicKey) {
  using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
  using EVP_PKEY_CTX_ptr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

  // 1. Create EVP_PKEY for private key (our key)
  EVP_PKEY_ptr pkey_priv(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, privateKey->data(), privateKey->size()), EVP_PKEY_free);
  if (!pkey_priv) {
    throw std::runtime_error("Failed to create private key: " + getOpenSSLError());
  }

  // 2. Create EVP_PKEY for public key (peer's key)
  EVP_PKEY_ptr pkey_pub(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, publicKey->data(), publicKey->size()), EVP_PKEY_free);
  if (!pkey_pub) {
    throw std::runtime_error("Failed to create public key: " + getOpenSSLError());
  }

  // 3. Create the context for the key exchange
  EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_from_pkey(NULL, pkey_priv.get(), NULL), EVP_PKEY_CTX_free);
  if (!ctx) {
    throw std::runtime_error("Failed to create key exchange context: " + getOpenSSLError());
  }

  // 4. Initialize the context
  if (EVP_PKEY_derive_init(ctx.get()) <= 0) {
    throw std::runtime_error("Failed to initialize key exchange: " + getOpenSSLError());
  }

  // 5. Provide the peer's public key
  if (EVP_PKEY_derive_set_peer(ctx.get(), pkey_pub.get()) <= 0) {
    throw std::runtime_error("Failed to set peer key: " + getOpenSSLError());
  }

  // 6. Determine the size of the shared secret
  size_t shared_secret_len;
  if (EVP_PKEY_derive(ctx.get(), NULL, &shared_secret_len) <= 0) {
    throw std::runtime_error("Failed to determine shared secret length: " + getOpenSSLError());
  }

  // 7. Allocate memory for the shared secret
  auto shared_secret = new uint8_t[shared_secret_len];

  // 8. Derive the shared secret
  if (EVP_PKEY_derive(ctx.get(), shared_secret, &shared_secret_len) <= 0) {
    delete[] shared_secret;
    throw std::runtime_error("Failed to derive shared secret: " + getOpenSSLError());
  }

  // 9. Return a newly-created ArrayBuffer from the raw buffer w/ cleanup
  return std::make_shared<NativeArrayBuffer>(shared_secret, shared_secret_len, [=]() { delete[] shared_secret; });
}

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
  // Clear any previous OpenSSL errors to prevent pollution
  clearOpenSSLErrors();

  if (this->curve.empty()) {
    throw std::runtime_error("EC curve not set. Call setCurve() first.");
  }

  // Store encoding configuration for later use in getPublicKey/getPrivateKey
  this->publicFormat_ = static_cast<int>(publicFormat);
  this->publicType_ = static_cast<int>(publicType);
  this->privateFormat_ = static_cast<int>(privateFormat);
  this->privateType_ = static_cast<int>(privateType);

  // Clean up existing key if any
  if (this->pkey != nullptr) {
    EVP_PKEY_free(this->pkey);
    this->pkey = nullptr;
  }

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
  // Clear any previous OpenSSL errors to prevent pollution
  clearOpenSSLErrors();

  size_t sig_len = 0;
  uint8_t* sig = NULL;
  EVP_MD_CTX* md_ctx = nullptr;
  EVP_PKEY_CTX* pkey_ctx = nullptr;

  // get key to use for signing
  EVP_PKEY* pkey = this->importPrivateKey(key);

  // key context
  md_ctx = EVP_MD_CTX_new();
  if (md_ctx == nullptr) {
    throw std::runtime_error("Error creating signing context");
  }

  pkey_ctx = EVP_PKEY_CTX_new_from_name(nullptr, this->curve.c_str(), nullptr);
  if (pkey_ctx == nullptr) {
    EVP_MD_CTX_free(md_ctx);
    throw std::runtime_error("Error creating signing context: " + this->curve);
  }

  if (EVP_DigestSignInit(md_ctx, &pkey_ctx, NULL, NULL, pkey) <= 0) {
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_CTX_free(pkey_ctx);
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
    delete[] sig;
    throw std::runtime_error("Failed to calculate signature");
  }

  // return value for JS
  std::shared_ptr<ArrayBuffer> signature = std::make_shared<NativeArrayBuffer>(sig, sig_len, [=]() { delete[] sig; });

  // Clean up
  EVP_MD_CTX_free(md_ctx);
  // Note: pkey_ctx is freed automatically by EVP_MD_CTX_free when using EVP_DigestSignInit

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
  // Clear any previous OpenSSL errors to prevent pollution
  clearOpenSSLErrors();

  // get key to use for verifying
  EVP_PKEY* pkey = this->importPublicKey(key);

  EVP_MD_CTX* md_ctx = nullptr;
  EVP_PKEY_CTX* pkey_ctx = nullptr;

  // key context
  md_ctx = EVP_MD_CTX_new();
  if (md_ctx == nullptr) {
    throw std::runtime_error("Error creating verify context");
  }

  pkey_ctx = EVP_PKEY_CTX_new_from_name(nullptr, this->curve.c_str(), nullptr);
  if (pkey_ctx == nullptr) {
    EVP_MD_CTX_free(md_ctx);
    throw std::runtime_error("Error creating verify context: " + this->curve);
  }

  if (EVP_DigestVerifyInit(md_ctx, &pkey_ctx, NULL, NULL, pkey) <= 0) {
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_CTX_free(pkey_ctx);
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

  // If format is DER (0) or PEM (1), export in SPKI format
  if (publicFormat_ == 0 || publicFormat_ == 1) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
      throw std::runtime_error("Failed to create BIO for public key export");
    }

    int result;
    if (publicFormat_ == 1) {
      // PEM format
      result = PEM_write_bio_PUBKEY(bio, this->pkey);
    } else {
      // DER format
      result = i2d_PUBKEY_bio(bio, this->pkey);
    }

    if (result != 1) {
      BIO_free(bio);
      throw std::runtime_error("Failed to export public key");
    }

    BUF_MEM* bptr;
    BIO_get_mem_ptr(bio, &bptr);

    uint8_t* data = new uint8_t[bptr->length];
    memcpy(data, bptr->data, bptr->length);
    size_t len = bptr->length;

    BIO_free(bio);

    return std::make_shared<NativeArrayBuffer>(data, len, [=]() { delete[] data; });
  }

  // Default: raw format
  size_t len = 0;
  EVP_PKEY_get_raw_public_key(this->pkey, nullptr, &len);
  uint8_t* publ = new uint8_t[len];
  EVP_PKEY_get_raw_public_key(this->pkey, publ, &len);

  return std::make_shared<NativeArrayBuffer>(publ, len, [=]() { delete[] publ; });
}

std::shared_ptr<ArrayBuffer> HybridEdKeyPair::getPrivateKey() {
  this->checkKeyPair();

  // If format is DER (0) or PEM (1), export in PKCS8 format
  if (privateFormat_ == 0 || privateFormat_ == 1) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
      throw std::runtime_error("Failed to create BIO for private key export");
    }

    int result;
    if (privateFormat_ == 1) {
      // PEM format (PKCS8)
      result = PEM_write_bio_PrivateKey(bio, this->pkey, nullptr, nullptr, 0, nullptr, nullptr);
    } else {
      // DER format (PKCS8)
      result = i2d_PrivateKey_bio(bio, this->pkey);
    }

    if (result != 1) {
      BIO_free(bio);
      throw std::runtime_error("Failed to export private key");
    }

    BUF_MEM* bptr;
    BIO_get_mem_ptr(bio, &bptr);

    uint8_t* data = new uint8_t[bptr->length];
    memcpy(data, bptr->data, bptr->length);
    size_t len = bptr->length;

    BIO_free(bio);

    return std::make_shared<NativeArrayBuffer>(data, len, [=]() { delete[] data; });
  }

  // Default: raw format
  size_t len = 0;
  EVP_PKEY_get_raw_private_key(this->pkey, nullptr, &len);
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
    // Determine key type from curve name
    int keyType = EVP_PKEY_ED25519;
    if (this->curve == "ed448" || this->curve == "Ed448") {
      keyType = EVP_PKEY_ED448;
    } else if (this->curve == "x25519" || this->curve == "X25519") {
      keyType = EVP_PKEY_X25519;
    } else if (this->curve == "x448" || this->curve == "X448") {
      keyType = EVP_PKEY_X448;
    }

    pkey = EVP_PKEY_new_raw_public_key(keyType, NULL, key.value()->data(), key.value()->size());
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
    // Determine key type from curve name
    int keyType = EVP_PKEY_ED25519;
    if (this->curve == "ed448" || this->curve == "Ed448") {
      keyType = EVP_PKEY_ED448;
    } else if (this->curve == "x25519" || this->curve == "X25519") {
      keyType = EVP_PKEY_X25519;
    } else if (this->curve == "x448" || this->curve == "X448") {
      keyType = EVP_PKEY_X448;
    }

    pkey = EVP_PKEY_new_raw_private_key(keyType, NULL, key.value()->data(), key.value()->size());
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
