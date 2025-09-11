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
#include <openssl/sha.h>
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

KeyObject HybridEcKeyPair::importKey(const std::string& format, const std::shared_ptr<ArrayBuffer>& keyData,
                                     const std::string& /* algorithm */, bool /* extractable */,
                                     const std::vector<std::string>& /* keyUsages */) {
  // Clean up any existing key
  if (this->pkey != nullptr) {
    EVP_PKEY_free(this->pkey);
    this->pkey = nullptr;
  }
  // Reset curve state to avoid interference between different uses
  this->curve.clear();

  // Import key from DER format
  if (format != "der") {
    throw std::runtime_error("Only DER format is supported for key import");
  }

  const unsigned char* keyPtr = static_cast<const unsigned char*>(keyData->data());
  size_t keyLen = keyData->size();

  // Try to import as public key first (SPKI format)
  EVP_PKEY* pkey = d2i_PUBKEY(nullptr, &keyPtr, keyLen);

  if (!pkey) {
    // Reset pointer and try as private key (PKCS8 format)
    keyPtr = static_cast<const unsigned char*>(keyData->data());

    // Try PKCS8 format for private keys
    BIO* pkcs8_bio = BIO_new_mem_buf(keyData->data(), static_cast<int>(keyData->size()));
    if (pkcs8_bio) {
      PKCS8_PRIV_KEY_INFO* p8inf = d2i_PKCS8_PRIV_KEY_INFO_bio(pkcs8_bio, nullptr);
      if (p8inf != nullptr) {
        EVP_PKEY* pkcs8_pkey = EVP_PKCS82PKEY(p8inf);
        PKCS8_PRIV_KEY_INFO_free(p8inf);
        BIO_free(pkcs8_bio);
        if (pkcs8_pkey != nullptr) {
          this->pkey = pkcs8_pkey;
          KeyObject keyObj;
          return keyObj;
        }
      }
      BIO_free(pkcs8_bio);
    }

    // Try to parse as SPKI (public key) with BIO
    BIO* spki_bio = BIO_new_mem_buf(keyData->data(), static_cast<int>(keyData->size()));
    if (spki_bio) {
      EVP_PKEY* spki_pkey = d2i_PUBKEY_bio(spki_bio, nullptr);
      BIO_free(spki_bio);
      if (spki_pkey != nullptr) {
        this->pkey = spki_pkey;
        KeyObject keyObj;
        return keyObj;
      }
    }

    throw std::runtime_error("Failed to import EC key from DER data");
  }

  this->pkey = pkey;

  // Return a placeholder KeyObject - this would need proper implementation
  // For now, we just need the key imported into this->pkey for sign/verify
  KeyObject keyObj;
  return keyObj;
}

std::shared_ptr<ArrayBuffer> HybridEcKeyPair::exportKey(const KeyObject& key, const std::string& format) {
  // Suppress unused parameter warning
  (void)key;

  if (!this->pkey) {
    throw std::runtime_error("No key pair generated");
  }

  if (format == "der-spki") {
    // Export public key in DER SPKI format
    int len = i2d_PUBKEY(this->pkey, nullptr);
    if (len <= 0) {
      throw std::runtime_error("Failed to get public key DER length");
    }

    std::vector<unsigned char> derData(len);
    unsigned char* ptr = derData.data();
    i2d_PUBKEY(this->pkey, &ptr);
    return ToNativeArrayBuffer(std::string(derData.begin(), derData.end()));
  } else if (format == "der-pkcs8") {
    // Export private key in DER PKCS8 format
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
    std::string derData(mem->data, mem->length);
    BIO_free(bio);

    return ToNativeArrayBuffer(derData);
  } else if (format == "pem-spki") {
    // Export public key in PEM SPKI format
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
      throw std::runtime_error("Failed to create BIO for public key export");
    }

    if (PEM_write_bio_PUBKEY(bio, this->pkey) != 1) {
      BIO_free(bio);
      throw std::runtime_error("Failed to export public key to PEM SPKI format");
    }

    BUF_MEM* mem;
    BIO_get_mem_ptr(bio, &mem);
    std::string pemData(mem->data, mem->length);
    BIO_free(bio);

    return ToNativeArrayBuffer(pemData);
  } else if (format == "pem-pkcs8") {
    // Export private key in PEM PKCS8 format
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
      throw std::runtime_error("Failed to create BIO for private key export");
    }

    if (PEM_write_bio_PKCS8PrivateKey(bio, this->pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
      BIO_free(bio);
      throw std::runtime_error("Failed to export private key to PEM PKCS8 format");
    }

    BUF_MEM* mem;
    BIO_get_mem_ptr(bio, &mem);
    std::string pemData(mem->data, mem->length);
    BIO_free(bio);

    return ToNativeArrayBuffer(pemData);
  }

  throw std::runtime_error("Unsupported export format: " + format);
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
  if (this->pkey == nullptr) {
    throw std::runtime_error("No private key available");
  }

  // Export private key in PKCS8 DER format
  BIO* bio = BIO_new(BIO_s_mem());
  if (i2d_PKCS8PrivateKey_bio(bio, this->pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
    BIO_free(bio);
    throw std::runtime_error("Failed to export private key");
  }

  BUF_MEM* mem;
  BIO_get_mem_ptr(bio, &mem);
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

std::shared_ptr<ArrayBuffer> HybridEcKeyPair::sign(const std::shared_ptr<ArrayBuffer>& data, const std::string& hashAlgorithm) {
  this->checkKeyPair();

  // Get the hash algorithm EVP_MD
  const EVP_MD* md = nullptr;
  if (hashAlgorithm == "SHA-256") {
    md = EVP_sha256();
  } else if (hashAlgorithm == "SHA-384") {
    md = EVP_sha384();
  } else if (hashAlgorithm == "SHA-512") {
    md = EVP_sha512();
  } else if (hashAlgorithm == "SHA-1") {
    md = EVP_sha1();
  } else {
    throw std::runtime_error("Unsupported hash algorithm: " + hashAlgorithm);
  }

  // Create signing context
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> md_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!md_ctx) {
    throw std::runtime_error("Failed to create message digest context");
  }

  // Initialize signing
  if (EVP_DigestSignInit(md_ctx.get(), nullptr, md, nullptr, this->pkey) <= 0) {
    throw std::runtime_error("Failed to initialize ECDSA signing");
  }

  // Update with data
  if (EVP_DigestSignUpdate(md_ctx.get(), data->data(), data->size()) <= 0) {
    throw std::runtime_error("Failed to update ECDSA signing with data");
  }

  // Get signature length
  size_t sig_len = 0;
  if (EVP_DigestSignFinal(md_ctx.get(), nullptr, &sig_len) <= 0) {
    throw std::runtime_error("Failed to get ECDSA signature length");
  }

  // Allocate signature buffer
  std::vector<uint8_t> signature(sig_len);

  // Get the actual signature
  if (EVP_DigestSignFinal(md_ctx.get(), signature.data(), &sig_len) <= 0) {
    throw std::runtime_error("Failed to generate ECDSA signature");
  }

  // Resize to actual signature length
  signature.resize(sig_len);

  // Convert to ArrayBuffer
  return ToNativeArrayBuffer(std::string(signature.begin(), signature.end()));
}

bool HybridEcKeyPair::verify(const std::shared_ptr<ArrayBuffer>& data, const std::shared_ptr<ArrayBuffer>& signature,
                             const std::string& hashAlgorithm) {
  this->checkKeyPair();

  // Get the hash algorithm EVP_MD
  const EVP_MD* md = nullptr;
  if (hashAlgorithm == "SHA-256") {
    md = EVP_sha256();
  } else if (hashAlgorithm == "SHA-384") {
    md = EVP_sha384();
  } else if (hashAlgorithm == "SHA-512") {
    md = EVP_sha512();
  } else if (hashAlgorithm == "SHA-1") {
    md = EVP_sha1();
  } else {
    throw std::runtime_error("Unsupported hash algorithm: " + hashAlgorithm);
  }

  // Create verification context
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> md_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!md_ctx) {
    throw std::runtime_error("Failed to create message digest context");
  }

  // Initialize verification
  if (EVP_DigestVerifyInit(md_ctx.get(), nullptr, md, nullptr, this->pkey) <= 0) {
    throw std::runtime_error("Failed to initialize ECDSA verification");
  }

  // Update with data
  if (EVP_DigestVerifyUpdate(md_ctx.get(), data->data(), data->size()) <= 0) {
    throw std::runtime_error("Failed to update ECDSA verification with data");
  }

  // Verify signature
  int result = EVP_DigestVerifyFinal(md_ctx.get(), static_cast<const unsigned char*>(signature->data()), signature->size());

  if (result < 0) {
    throw std::runtime_error("ECDSA verification failed with error");
  }

  return result == 1;
}

void HybridEcKeyPair::checkKeyPair() {
  if (this->pkey == nullptr) {
    throw std::runtime_error("EC KeyPair not initialized");
  }
}

} // namespace margelo::nitro::crypto
