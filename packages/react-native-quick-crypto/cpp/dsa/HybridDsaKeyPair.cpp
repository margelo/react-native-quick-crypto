#include "HybridDsaKeyPair.hpp"

#include <NitroModules/ArrayBuffer.hpp>
#include <NitroModules/Promise.hpp>
#include <memory>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdexcept>
#include <string>

namespace margelo::nitro::crypto {

void HybridDsaKeyPair::setModulusLength(double modulusLength) {
  modulusLength_ = static_cast<int>(modulusLength);
}

void HybridDsaKeyPair::setDivisorLength(double divisorLength) {
  divisorLength_ = static_cast<int>(divisorLength);
}

std::shared_ptr<Promise<void>> HybridDsaKeyPair::generateKeyPair() {
  return Promise<void>::async([this]() { this->generateKeyPairSync(); });
}

void HybridDsaKeyPair::generateKeyPairSync() {
  if (modulusLength_ <= 0) {
    throw std::runtime_error("DSA modulusLength must be set before generating key pair");
  }

  if (pkey != nullptr) {
    EVP_PKEY_free(pkey);
    pkey = nullptr;
  }

  // Step 1: Generate DSA parameters
  std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> param_ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, nullptr), EVP_PKEY_CTX_free);

  if (!param_ctx) {
    throw std::runtime_error("DSA: failed to create parameter context");
  }

  if (EVP_PKEY_paramgen_init(param_ctx.get()) <= 0) {
    throw std::runtime_error("DSA: failed to initialize parameter generation");
  }

  if (EVP_PKEY_CTX_set_dsa_paramgen_bits(param_ctx.get(), modulusLength_) <= 0) {
    throw std::runtime_error("DSA: failed to set modulus length");
  }

  if (divisorLength_ >= 0) {
    if (EVP_PKEY_CTX_set_dsa_paramgen_q_bits(param_ctx.get(), divisorLength_) <= 0) {
      throw std::runtime_error("DSA: failed to set divisor length");
    }
  }

  EVP_PKEY* raw_params = nullptr;
  if (EVP_PKEY_paramgen(param_ctx.get(), &raw_params) <= 0) {
    throw std::runtime_error("DSA: failed to generate parameters");
  }

  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> params(raw_params, EVP_PKEY_free);

  // Step 2: Generate key pair from parameters
  std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> key_ctx(EVP_PKEY_CTX_new(params.get(), nullptr), EVP_PKEY_CTX_free);

  if (!key_ctx) {
    throw std::runtime_error("DSA: failed to create key generation context");
  }

  if (EVP_PKEY_keygen_init(key_ctx.get()) <= 0) {
    throw std::runtime_error("DSA: failed to initialize key generation");
  }

  EVP_PKEY* raw_pkey = nullptr;
  if (EVP_PKEY_keygen(key_ctx.get(), &raw_pkey) <= 0) {
    throw std::runtime_error("DSA: failed to generate key pair");
  }

  pkey = raw_pkey;
}

std::shared_ptr<ArrayBuffer> HybridDsaKeyPair::getPublicKey() {
  if (pkey == nullptr) {
    throw std::runtime_error("DSA: no key pair generated");
  }

  BIO* bio = BIO_new(BIO_s_mem());
  if (!bio) {
    throw std::runtime_error("DSA: failed to create BIO for public key export");
  }

  if (i2d_PUBKEY_bio(bio, pkey) != 1) {
    BIO_free(bio);
    throw std::runtime_error("DSA: failed to export public key");
  }

  BUF_MEM* mem;
  BIO_get_mem_ptr(bio, &mem);
  std::string derData(mem->data, mem->length);
  BIO_free(bio);

  return ToNativeArrayBuffer(derData);
}

std::shared_ptr<ArrayBuffer> HybridDsaKeyPair::getPrivateKey() {
  if (pkey == nullptr) {
    throw std::runtime_error("DSA: no key pair generated");
  }

  BIO* bio = BIO_new(BIO_s_mem());
  if (!bio) {
    throw std::runtime_error("DSA: failed to create BIO for private key export");
  }

  if (i2d_PKCS8PrivateKey_bio(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
    BIO_free(bio);
    throw std::runtime_error("DSA: failed to export private key");
  }

  BUF_MEM* mem;
  BIO_get_mem_ptr(bio, &mem);
  std::string derData(mem->data, mem->length);
  BIO_free(bio);

  return ToNativeArrayBuffer(derData);
}

} // namespace margelo::nitro::crypto
