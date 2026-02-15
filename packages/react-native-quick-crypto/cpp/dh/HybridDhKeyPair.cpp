#include "HybridDhKeyPair.hpp"

#include <NitroModules/ArrayBuffer.hpp>
#include <NitroModules/Promise.hpp>
#include <memory>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/buffer.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdexcept>
#include <string>

// Suppress deprecation warnings for DH_* functions
// Node.js ncrypto uses the same pattern — these APIs work but are deprecated in OpenSSL 3.x
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

namespace margelo::nitro::crypto {

using BN_ptr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using DH_ptr = std::unique_ptr<DH, decltype(&DH_free)>;
using EVP_PKEY_CTX_ptr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

void HybridDhKeyPair::setPrimeLength(double primeLength) {
  primeLength_ = static_cast<int>(primeLength);
}

void HybridDhKeyPair::setPrime(const std::shared_ptr<ArrayBuffer>& prime) {
  prime_.assign(prime->data(), prime->data() + prime->size());
}

void HybridDhKeyPair::setGenerator(double generator) {
  generator_ = static_cast<int>(generator);
}

void HybridDhKeyPair::setGroupName(const std::string& groupName) {
  groupName_ = groupName;
}

std::shared_ptr<Promise<void>> HybridDhKeyPair::generateKeyPair() {
  return Promise<void>::async([this]() { this->generateKeyPairSync(); });
}

void HybridDhKeyPair::generateKeyPairSync() {
  pkey_.reset();

  EVP_PKEY* params = nullptr;

  if (!prime_.empty()) {
    // Mode B: Custom prime provided as binary
    DH_ptr dh(DH_new(), DH_free);
    if (!dh) {
      throw std::runtime_error("DH: failed to create DH structure");
    }

    BIGNUM* p = BN_bin2bn(prime_.data(), static_cast<int>(prime_.size()), nullptr);
    BIGNUM* g = BN_new();
    if (!p || !g) {
      if (p)
        BN_free(p);
      if (g)
        BN_free(g);
      throw std::runtime_error("DH: failed to create BIGNUM parameters");
    }
    BN_set_word(g, static_cast<unsigned long>(generator_));

    if (DH_set0_pqg(dh.get(), p, nullptr, g) != 1) {
      BN_free(p);
      BN_free(g);
      throw std::runtime_error("DH: failed to set DH parameters");
    }

    EVP_PKEY* pkey_params = EVP_PKEY_new();
    if (!pkey_params) {
      throw std::runtime_error("DH: failed to create EVP_PKEY for parameters");
    }

    if (EVP_PKEY_assign_DH(pkey_params, dh.get()) != 1) {
      EVP_PKEY_free(pkey_params);
      throw std::runtime_error("DH: failed to assign DH to EVP_PKEY");
    }
    dh.release(); // EVP_PKEY now owns it

    params = pkey_params;

  } else if (primeLength_ > 0) {
    // Mode C: Generate random prime of given size
    EVP_PKEY_CTX_ptr pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_DH, nullptr), EVP_PKEY_CTX_free);
    if (!pctx) {
      throw std::runtime_error("DH: failed to create parameter context");
    }

    if (EVP_PKEY_paramgen_init(pctx.get()) <= 0) {
      throw std::runtime_error("DH: failed to initialize parameter generation");
    }

    if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(pctx.get(), primeLength_) <= 0) {
      throw std::runtime_error("DH: failed to set prime length");
    }

    if (EVP_PKEY_CTX_set_dh_paramgen_generator(pctx.get(), generator_) <= 0) {
      throw std::runtime_error("DH: failed to set generator");
    }

    if (EVP_PKEY_paramgen(pctx.get(), &params) <= 0) {
      throw std::runtime_error("DH: failed to generate parameters");
    }
  } else {
    throw std::runtime_error("DH: either prime, primeLength, or groupName must be set");
  }

  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> params_guard(params, EVP_PKEY_free);

  // Generate key pair from parameters
  EVP_PKEY_CTX_ptr kctx(EVP_PKEY_CTX_new(params, nullptr), EVP_PKEY_CTX_free);
  if (!kctx) {
    throw std::runtime_error("DH: failed to create keygen context");
  }

  if (EVP_PKEY_keygen_init(kctx.get()) <= 0) {
    throw std::runtime_error("DH: failed to initialize key generation");
  }

  EVP_PKEY* raw_pkey = nullptr;
  if (EVP_PKEY_keygen(kctx.get(), &raw_pkey) <= 0) {
    throw std::runtime_error("DH: failed to generate key pair");
  }

  pkey_.reset(raw_pkey);
}

std::shared_ptr<ArrayBuffer> HybridDhKeyPair::getPublicKey() {
  if (!pkey_) {
    throw std::runtime_error("DH: no key pair generated");
  }

  BIO* bio = BIO_new(BIO_s_mem());
  if (!bio) {
    throw std::runtime_error("DH: failed to create BIO for public key export");
  }

  if (i2d_PUBKEY_bio(bio, pkey_.get()) != 1) {
    BIO_free(bio);
    throw std::runtime_error("DH: failed to export public key");
  }

  BUF_MEM* mem;
  BIO_get_mem_ptr(bio, &mem);
  std::string derData(mem->data, mem->length);
  BIO_free(bio);

  return ToNativeArrayBuffer(derData);
}

std::shared_ptr<ArrayBuffer> HybridDhKeyPair::getPrivateKey() {
  if (!pkey_) {
    throw std::runtime_error("DH: no key pair generated");
  }

  BIO* bio = BIO_new(BIO_s_mem());
  if (!bio) {
    throw std::runtime_error("DH: failed to create BIO for private key export");
  }

  if (i2d_PKCS8PrivateKey_bio(bio, pkey_.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
    BIO_free(bio);
    throw std::runtime_error("DH: failed to export private key");
  }

  BUF_MEM* mem;
  BIO_get_mem_ptr(bio, &mem);
  std::string derData(mem->data, mem->length);
  BIO_free(bio);

  return ToNativeArrayBuffer(derData);
}

#pragma clang diagnostic pop

} // namespace margelo::nitro::crypto
