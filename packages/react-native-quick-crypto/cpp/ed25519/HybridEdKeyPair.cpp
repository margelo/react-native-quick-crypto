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
  using EVP_PKEY_CTX_ptr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

  // Determine key type from curve name
  int keyType = EVP_PKEY_X25519;
  if (this->curve == "x448" || this->curve == "X448") {
    keyType = EVP_PKEY_X448;
  }

  // 1. Create EVP_PKEY for private key (our key)
  EVP_PKEY_ptr pkey_priv(EVP_PKEY_new_raw_private_key(keyType, NULL, privateKey->data(), privateKey->size()), EVP_PKEY_free);
  if (!pkey_priv) {
    throw std::runtime_error("Failed to create private key: " + getOpenSSLError());
  }

  // 2. Create EVP_PKEY for public key (peer's key)
  EVP_PKEY_ptr pkey_pub(EVP_PKEY_new_raw_public_key(keyType, NULL, publicKey->data(), publicKey->size()), EVP_PKEY_free);
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
  auto shared_secret = std::make_unique<uint8_t[]>(shared_secret_len);

  // 8. Derive the shared secret
  if (EVP_PKEY_derive(ctx.get(), shared_secret.get(), &shared_secret_len) <= 0) {
    throw std::runtime_error("Failed to derive shared secret: " + getOpenSSLError());
  }

  // 9. Return a newly-created ArrayBuffer from the raw buffer w/ cleanup
  uint8_t* raw_ptr = shared_secret.get();
  return std::make_shared<NativeArrayBuffer>(shared_secret.release(), shared_secret_len, [raw_ptr]() { delete[] raw_ptr; });
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
  this->pkey_.reset();

  std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> pctx(EVP_PKEY_CTX_new_from_name(nullptr, this->curve.c_str(), nullptr),
                                                                   EVP_PKEY_CTX_free);
  if (!pctx) {
    throw std::runtime_error("Invalid curve name: " + this->curve);
  }

  // keygen init
  if (EVP_PKEY_keygen_init(pctx.get()) <= 0) {
    throw std::runtime_error("Failed to initialize keygen");
  }

  // generate key
  EVP_PKEY* raw_pkey = nullptr;
  EVP_PKEY_keygen(pctx.get(), &raw_pkey);
  if (raw_pkey == nullptr) {
    throw std::runtime_error("Failed to generate key");
  }
  this->pkey_.reset(raw_pkey);
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

  // get key to use for signing
  EVP_PKEY_ptr pkey = this->importPrivateKey(key);

  // key context
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> md_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!md_ctx) {
    throw std::runtime_error("Error creating signing context");
  }

  if (EVP_DigestSignInit(md_ctx.get(), nullptr, NULL, NULL, pkey.get()) <= 0) {
    throw std::runtime_error("Failed to initialize signing: " + getOpenSSLError());
  }

  // Calculate the required size for the signature by passing a NULL buffer.
  size_t sig_len = 0;
  if (EVP_DigestSign(md_ctx.get(), NULL, &sig_len, message.get()->data(), message.get()->size()) <= 0) {
    throw std::runtime_error("Failed to calculate signature size");
  }
  auto sig = std::make_unique<uint8_t[]>(sig_len);

  // Actually calculate the signature
  if (EVP_DigestSign(md_ctx.get(), sig.get(), &sig_len, message.get()->data(), message.get()->size()) <= 0) {
    throw std::runtime_error("Failed to calculate signature");
  }

  // return value for JS
  uint8_t* raw_ptr = sig.get();
  return std::make_shared<NativeArrayBuffer>(sig.release(), sig_len, [raw_ptr]() { delete[] raw_ptr; });
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
  EVP_PKEY_ptr pkey = this->importPublicKey(key);

  // key context
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> md_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!md_ctx) {
    throw std::runtime_error("Error creating verify context");
  }

  if (EVP_DigestVerifyInit(md_ctx.get(), nullptr, NULL, NULL, pkey.get()) <= 0) {
    throw std::runtime_error("Failed to initialize verify: " + getOpenSSLError());
  }

  // verify
  auto res = EVP_DigestVerify(md_ctx.get(), signature.get()->data(), signature.get()->size(), message.get()->data(), message.get()->size());

  // return value for JS
  if (res < 0) {
    throw std::runtime_error("Failed to verify");
  }
  return res == 1; // true if 1, false if 0
}

std::shared_ptr<ArrayBuffer> HybridEdKeyPair::getPublicKey() {
  this->checkKeyPair();

  // If format is DER (0) or PEM (1), export in SPKI format
  if (publicFormat_ == 0 || publicFormat_ == 1) {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
    if (!bio) {
      throw std::runtime_error("Failed to create BIO for public key export");
    }

    int result;
    if (publicFormat_ == 1) {
      // PEM format
      result = PEM_write_bio_PUBKEY(bio.get(), this->pkey_.get());
    } else {
      // DER format
      result = i2d_PUBKEY_bio(bio.get(), this->pkey_.get());
    }

    if (result != 1) {
      throw std::runtime_error("Failed to export public key");
    }

    BUF_MEM* bptr;
    BIO_get_mem_ptr(bio.get(), &bptr);

    auto data = std::make_unique<uint8_t[]>(bptr->length);
    memcpy(data.get(), bptr->data, bptr->length);
    size_t len = bptr->length;

    uint8_t* raw_ptr = data.get();
    return std::make_shared<NativeArrayBuffer>(data.release(), len, [raw_ptr]() { delete[] raw_ptr; });
  }

  // Default: raw format
  size_t len = 0;
  EVP_PKEY_get_raw_public_key(this->pkey_.get(), nullptr, &len);
  auto publ = std::make_unique<uint8_t[]>(len);
  EVP_PKEY_get_raw_public_key(this->pkey_.get(), publ.get(), &len);

  uint8_t* raw_ptr = publ.get();
  return std::make_shared<NativeArrayBuffer>(publ.release(), len, [raw_ptr]() { delete[] raw_ptr; });
}

std::shared_ptr<ArrayBuffer> HybridEdKeyPair::getPrivateKey() {
  this->checkKeyPair();

  // If format is DER (0) or PEM (1), export in PKCS8 format
  if (privateFormat_ == 0 || privateFormat_ == 1) {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
    if (!bio) {
      throw std::runtime_error("Failed to create BIO for private key export");
    }

    int result;
    if (privateFormat_ == 1) {
      // PEM format (PKCS8)
      result = PEM_write_bio_PrivateKey(bio.get(), this->pkey_.get(), nullptr, nullptr, 0, nullptr, nullptr);
    } else {
      // DER format (PKCS8)
      result = i2d_PrivateKey_bio(bio.get(), this->pkey_.get());
    }

    if (result != 1) {
      throw std::runtime_error("Failed to export private key");
    }

    BUF_MEM* bptr;
    BIO_get_mem_ptr(bio.get(), &bptr);

    auto data = std::make_unique<uint8_t[]>(bptr->length);
    memcpy(data.get(), bptr->data, bptr->length);
    size_t len = bptr->length;

    // Zero the BIO's internal buffer — it held private key bytes (PEM/DER PKCS8)
    secureZero(bptr->data, bptr->length);

    uint8_t* raw_ptr = data.get();
    return std::make_shared<NativeArrayBuffer>(data.release(), len, [raw_ptr]() { delete[] raw_ptr; });
  }

  // Default: raw format
  size_t len = 0;
  EVP_PKEY_get_raw_private_key(this->pkey_.get(), nullptr, &len);
  auto priv = std::make_unique<uint8_t[]>(len);
  EVP_PKEY_get_raw_private_key(this->pkey_.get(), priv.get(), &len);

  uint8_t* raw_ptr = priv.get();
  return std::make_shared<NativeArrayBuffer>(priv.release(), len, [raw_ptr]() { delete[] raw_ptr; });
}

void HybridEdKeyPair::checkKeyPair() {
  if (!this->pkey_) {
    throw std::runtime_error("Keypair not initialized");
  }
}

void HybridEdKeyPair::setCurve(const std::string& curve) {
  this->curve = curve;
}

auto HybridEdKeyPair::importPublicKey(const std::optional<std::shared_ptr<ArrayBuffer>>& key) -> EVP_PKEY_ptr {
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

    EVP_PKEY_ptr pkey(EVP_PKEY_new_raw_public_key(keyType, NULL, key.value()->data(), key.value()->size()), EVP_PKEY_free);
    if (!pkey) {
      throw std::runtime_error("Failed to read public key");
    }
    return pkey;
  }
  this->checkKeyPair();
  EVP_PKEY_up_ref(this->pkey_.get());
  return EVP_PKEY_ptr(this->pkey_.get(), EVP_PKEY_free);
}

auto HybridEdKeyPair::importPrivateKey(const std::optional<std::shared_ptr<ArrayBuffer>>& key) -> EVP_PKEY_ptr {
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

    EVP_PKEY_ptr pkey(EVP_PKEY_new_raw_private_key(keyType, NULL, key.value()->data(), key.value()->size()), EVP_PKEY_free);
    if (!pkey) {
      throw std::runtime_error("Failed to read private key");
    }
    return pkey;
  }
  this->checkKeyPair();
  EVP_PKEY_up_ref(this->pkey_.get());
  return EVP_PKEY_ptr(this->pkey_.get(), EVP_PKEY_free);
}

} // namespace margelo::nitro::crypto
