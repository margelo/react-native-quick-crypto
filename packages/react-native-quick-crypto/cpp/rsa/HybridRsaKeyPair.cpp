#include <NitroModules/ArrayBuffer.hpp>
#include <NitroModules/Promise.hpp>
#include <memory>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <stdexcept>
#include <string>

#include "HybridRsaKeyPair.hpp"
#include "QuickCryptoUtils.hpp"

namespace margelo::nitro::crypto {

std::shared_ptr<Promise<void>> HybridRsaKeyPair::generateKeyPair() {
  return Promise<void>::async([this]() { this->generateKeyPairSync(); });
}

void HybridRsaKeyPair::generateKeyPairSync() {
  // Clean up existing key if any
  if (this->pkey != nullptr) {
    EVP_PKEY_free(this->pkey);
    this->pkey = nullptr;
  }

  // Create key generation context
  std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);

  if (!ctx) {
    throw std::runtime_error("Failed to create RSA key generation context");
  }

  if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
    throw std::runtime_error("Failed to initialize RSA key generation");
  }

  // Set modulus length
  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), this->modulusLength) <= 0) {
    throw std::runtime_error("Failed to set RSA modulus length");
  }

  // Set public exponent
  std::unique_ptr<BIGNUM, decltype(&BN_free)> exponent(BN_new(), BN_free);
  if (!exponent) {
    throw std::runtime_error("Failed to create BIGNUM for public exponent");
  }

  // Default to 65537 (0x10001) if no public exponent is set
  if (this->publicExponent.empty()) {
    if (BN_set_word(exponent.get(), RSA_F4) != 1) {
      throw std::runtime_error("Failed to set default public exponent");
    }
  } else {
    if (BN_bin2bn(this->publicExponent.data(), this->publicExponent.size(), exponent.get()) == nullptr) {
      throw std::runtime_error("Failed to convert public exponent to BIGNUM");
    }
  }

  if (EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx.get(), exponent.get()) <= 0) {
    throw std::runtime_error("Failed to set RSA public exponent");
  }

  // Generate the key pair
  EVP_PKEY* raw_pkey = nullptr;
  if (EVP_PKEY_keygen(ctx.get(), &raw_pkey) <= 0) {
    throw std::runtime_error("Failed to generate RSA key pair");
  }

  this->pkey = raw_pkey;
}

void HybridRsaKeyPair::setModulusLength(double modulusLength) {
  this->modulusLength = static_cast<int>(modulusLength);
}

void HybridRsaKeyPair::setPublicExponent(const std::shared_ptr<ArrayBuffer>& publicExponent) {
  if (publicExponent && publicExponent->size() > 0) {
    const uint8_t* data = publicExponent->data();
    this->publicExponent.assign(data, data + publicExponent->size());
  }
}

void HybridRsaKeyPair::setHashAlgorithm(const std::string& hashAlgorithm) {
  this->hashAlgorithm = hashAlgorithm;
}

std::shared_ptr<ArrayBuffer> HybridRsaKeyPair::getPublicKey() {
  this->checkKeyPair();

  // Export as DER format using direct OpenSSL calls
  BIO* bio = BIO_new(BIO_s_mem());
  if (!bio) {
    throw std::runtime_error("Failed to create BIO for public key export");
  }

  if (i2d_PUBKEY_bio(bio, this->pkey) != 1) {
    BIO_free(bio);
    throw std::runtime_error("Failed to export public key to DER format");
  }

  BUF_MEM* mem;
  BIO_get_mem_ptr(bio, &mem);

  // Create a string from the DER data and use ToNativeArrayBuffer utility
  std::string derData(mem->data, mem->length);
  BIO_free(bio);

  return ToNativeArrayBuffer(derData);
}

std::shared_ptr<ArrayBuffer> HybridRsaKeyPair::getPrivateKey() {
  this->checkKeyPair();

  // Export as DER format in PKCS8 format using direct OpenSSL calls
  BIO* bio = BIO_new(BIO_s_mem());
  if (!bio) {
    throw std::runtime_error("Failed to create BIO for private key export");
  }

  if (i2d_PKCS8PrivateKey_bio(bio, this->pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
    BIO_free(bio);
    throw std::runtime_error("Failed to export private key to DER PKCS8 format");
  }

  BUF_MEM* mem;
  BIO_get_mem_ptr(bio, &mem);

  // Create a string from the DER data and use ToNativeArrayBuffer utility
  std::string derData(mem->data, mem->length);
  BIO_free(bio);

  return ToNativeArrayBuffer(derData);
}

KeyObject HybridRsaKeyPair::importKey(const std::string& /* format */, const std::shared_ptr<ArrayBuffer>& /* keyData */,
                                      const std::string& /* algorithm */, bool /* extractable */,
                                      const std::vector<std::string>& /* keyUsages */) {
  throw std::runtime_error("HybridRsaKeyPair::importKey() is not yet implemented");
}

std::shared_ptr<ArrayBuffer> HybridRsaKeyPair::exportKey(const KeyObject& /* key */, const std::string& /* format */) {
  throw std::runtime_error("HybridRsaKeyPair::exportKey() is not yet implemented");
}

void HybridRsaKeyPair::checkKeyPair() {
  if (this->pkey == nullptr) {
    throw std::runtime_error("RSA KeyPair not initialized");
  }
}

} // namespace margelo::nitro::crypto
