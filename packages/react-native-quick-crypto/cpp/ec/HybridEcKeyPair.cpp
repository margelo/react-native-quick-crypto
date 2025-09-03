#include <NitroModules/ArrayBuffer.hpp>
#include <NitroModules/Promise.hpp>
#include <memory>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <stdexcept>
#include <string>

// OpenSSL EC parameter encoding constants
#ifndef OPENSSL_EC_EXPLICIT_CURVE
#define OPENSSL_EC_EXPLICIT_CURVE 0x000
#endif
#ifndef OPENSSL_EC_NAMED_CURVE
#define OPENSSL_EC_NAMED_CURVE 0x001
#endif

#include "HybridEcKeyPair.hpp"
#include "Utils.hpp"

namespace margelo::nitro::crypto {

std::shared_ptr<Promise<void>> HybridEcKeyPair::generateKeyPair() {
  return Promise<void>::async([this]() { this->generateKeyPairSync(); });
}

void HybridEcKeyPair::generateKeyPairSync() {
  if (this->curve.empty()) {
    throw std::runtime_error("EC curve not set. Call setCurve() first.");
  }

  // Clean up existing key if any
  if (this->pkey != nullptr) {
    EVP_PKEY_free(this->pkey);
    this->pkey = nullptr;
  }

  // Get curve NID from curve name
  int curve_nid = GetCurveFromName(this->curve.c_str());
  if (curve_nid == NID_undef) {
    throw std::runtime_error("Invalid or unsupported curve: " + this->curve);
  }

  std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> key_ctx(nullptr, EVP_PKEY_CTX_free);

  // Handle special curves (Ed25519, X25519, etc.)
  switch (curve_nid) {
    case EVP_PKEY_ED25519:
    case EVP_PKEY_ED448:
    case EVP_PKEY_X25519:
    case EVP_PKEY_X448:
      key_ctx.reset(EVP_PKEY_CTX_new_id(curve_nid, nullptr));
      break;
    default: {
      // Standard EC curves
      std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> param_ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free);

      if (!param_ctx) {
        throw std::runtime_error("Failed to create parameter context");
      }

      if (EVP_PKEY_paramgen_init(param_ctx.get()) <= 0) {
        throw std::runtime_error("Failed to initialize parameter generation");
      }

      if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(param_ctx.get(), curve_nid) <= 0) {
        throw std::runtime_error("Failed to set curve NID");
      }

      if (EVP_PKEY_CTX_set_ec_param_enc(param_ctx.get(), OPENSSL_EC_NAMED_CURVE) <= 0) {
        throw std::runtime_error("Failed to set parameter encoding");
      }

      EVP_PKEY* raw_params = nullptr;
      if (EVP_PKEY_paramgen(param_ctx.get(), &raw_params) <= 0) {
        throw std::runtime_error("Failed to generate parameters");
      }

      std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key_params(raw_params, EVP_PKEY_free);
      key_ctx.reset(EVP_PKEY_CTX_new(key_params.get(), nullptr));
      break;
    }
  }

  if (!key_ctx) {
    throw std::runtime_error("Failed to create key generation context");
  }

  if (EVP_PKEY_keygen_init(key_ctx.get()) <= 0) {
    throw std::runtime_error("Failed to initialize key generation");
  }

  EVP_PKEY* raw_pkey = nullptr;
  if (EVP_PKEY_keygen(key_ctx.get(), &raw_pkey) <= 0) {
    throw std::runtime_error("Failed to generate EC key pair");
  }

  this->pkey = raw_pkey;
}

KeyObject HybridEcKeyPair::importKey(const std::string& format, const std::shared_ptr<ArrayBuffer>& keyData, const std::string& algorithm,
                                     bool extractable, const std::vector<std::string>& keyUsages) {
  throw std::runtime_error("HybridEcKeyPair::importKey() is not yet implemented");
}

std::shared_ptr<ArrayBuffer> HybridEcKeyPair::exportKey(const KeyObject& key, const std::string& format) {
  throw std::runtime_error("HybridEcKeyPair::exportKey() is not yet implemented");
}

std::shared_ptr<ArrayBuffer> HybridEcKeyPair::getPublicKey() {
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

std::shared_ptr<ArrayBuffer> HybridEcKeyPair::getPrivateKey() {
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

void HybridEcKeyPair::setCurve(const std::string& curve) {
  this->curve = curve;
}

int HybridEcKeyPair::GetCurveFromName(const char* name) {
  // Handle NIST curve name mappings first
  std::string curve_name(name);
  if (curve_name == "P-256") {
    return NID_X9_62_prime256v1;
  } else if (curve_name == "P-384") {
    return NID_secp384r1;
  } else if (curve_name == "P-521") {
    return NID_secp521r1;
  } else if (curve_name == "secp256k1") {
    return NID_secp256k1;
  }

  // Try standard OpenSSL name resolution
  int nid = OBJ_txt2nid(name);
  if (nid == NID_undef) {
    // Try short names
    nid = OBJ_sn2nid(name);
  }
  if (nid == NID_undef) {
    // Try long names
    nid = OBJ_ln2nid(name);
  }
  return nid;
}

void HybridEcKeyPair::checkKeyPair() {
  if (this->pkey == nullptr) {
    throw std::runtime_error("EC KeyPair not initialized");
  }
}

} // namespace margelo::nitro::crypto
