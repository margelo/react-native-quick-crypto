#include "HybridSignHandle.hpp"

#include "../keys/HybridKeyObjectHandle.hpp"
#include "QuickCryptoUtils.hpp"
#include "SignUtils.hpp"

#include <cstring>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#if OPENSSL_VERSION_NUMBER >= 0x30500000L
#define RNQC_HAS_ML_DSA 1
#else
#define RNQC_HAS_ML_DSA 0
#endif

namespace margelo::nitro::crypto {

using margelo::nitro::NativeArrayBuffer;

HybridSignHandle::~HybridSignHandle() {
  if (md_ctx) {
    EVP_MD_CTX_free(md_ctx);
    md_ctx = nullptr;
  }
}

void HybridSignHandle::init(const std::string& algorithm) {
  algorithm_name = algorithm;

  // For ML-DSA and other pure signature schemes, algorithm may be empty/null
  if (!algorithm.empty()) {
    md = getDigestByName(algorithm);

    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
      throw std::runtime_error("Failed to create message digest context");
    }

    if (EVP_DigestInit_ex(md_ctx, md, nullptr) <= 0) {
      EVP_MD_CTX_free(md_ctx);
      md_ctx = nullptr;
      throw std::runtime_error("Failed to initialize message digest");
    }
  } else {
    // No digest for pure signature schemes like ML-DSA
    md = nullptr;
    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
      throw std::runtime_error("Failed to create message digest context");
    }
  }
}

void HybridSignHandle::update(const std::shared_ptr<ArrayBuffer>& data) {
  if (!md_ctx) {
    throw std::runtime_error("Sign not initialized");
  }

  // Accumulate raw data for potential one-shot signing (Ed25519/Ed448/ML-DSA)
  const uint8_t* ptr = reinterpret_cast<const uint8_t*>(data->data());
  data_buffer.insert(data_buffer.end(), ptr, ptr + data->size());

  // Only update digest if we have one (not needed for pure signature schemes)
  if (md != nullptr) {
    if (EVP_DigestUpdate(md_ctx, data->data(), data->size()) <= 0) {
      unsigned long err = ERR_get_error();
      char err_buf[256];
      ERR_error_string_n(err, err_buf, sizeof(err_buf));
      throw std::runtime_error("Failed to update digest: " + std::string(err_buf));
    }
  }
}

// Check if key type requires one-shot signing (Ed25519, Ed448, ML-DSA)
static bool isOneShotVariant(EVP_PKEY* pkey) {
  int type = EVP_PKEY_id(pkey);
#if RNQC_HAS_ML_DSA
  return type == EVP_PKEY_ED25519 || type == EVP_PKEY_ED448 || type == EVP_PKEY_ML_DSA_44 || type == EVP_PKEY_ML_DSA_65 ||
         type == EVP_PKEY_ML_DSA_87;
#else
  return type == EVP_PKEY_ED25519 || type == EVP_PKEY_ED448;
#endif
}

// RAII owners for short-lived OpenSSL handles used in this method. EVP_MD_CTX
// transitively owns its EVP_PKEY_CTX after a successful EVP_DigestSignInit, so
// we deliberately rely on EVP_MD_CTX_free to clean both up; the standalone
// EvpPkeyCtxPtr alias is kept only for the RSA/ECDSA branch, where we
// allocate the PKEY_CTX directly via EVP_PKEY_CTX_new.
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

std::shared_ptr<ArrayBuffer> HybridSignHandle::sign(const std::shared_ptr<HybridKeyObjectHandleSpec>& keyHandle,
                                                    std::optional<double> padding, std::optional<double> saltLength,
                                                    std::optional<double> dsaEncoding) {
  if (!md_ctx) {
    throw std::runtime_error("Sign not initialized");
  }

  auto keyHandleImpl = std::static_pointer_cast<HybridKeyObjectHandle>(keyHandle);
  EVP_PKEY* pkey = keyHandleImpl->getKeyObjectData().GetAsymmetricKey().get();

  if (!pkey) {
    throw std::runtime_error("Invalid private key for signing");
  }

  size_t sig_len = 0;
  std::unique_ptr<uint8_t[]> sig_buf;

  int pkey_type = EVP_PKEY_id(pkey);
  bool is_one_shot = isOneShotVariant(pkey);

  // Ed25519/Ed448/ML-DSA require one-shot signing with EVP_DigestSign
  // Also use one-shot path if no digest was specified (md == nullptr)
  if (is_one_shot || md == nullptr) {
    EvpMdCtxPtr sign_ctx{EVP_MD_CTX_new(), EVP_MD_CTX_free};
    if (!sign_ctx) {
      throw std::runtime_error("Failed to create signing context");
    }

    // Let OpenSSL allocate the PKEY_CTX from the key's keymgmt. On success the
    // EVP_MD_CTX assumes ownership and EVP_MD_CTX_free will dispose it; on
    // failure pkey_ctx_raw stays nullptr, so there is nothing to leak. This
    // mirrors ncrypto's EVPMDCtxPointer::signInit (Node.js deps/ncrypto/ncrypto.cc
    // and ~/dev/ncrypto/src/ncrypto.cpp), which works for RSA, ECDSA, Ed25519,
    // Ed448 and ML-DSA without any algorithm-name pre-creation.
    EVP_PKEY_CTX* pkey_ctx_raw = nullptr;
    if (EVP_DigestSignInit(sign_ctx.get(), &pkey_ctx_raw, nullptr, nullptr, pkey) <= 0) {
      throw std::runtime_error("Failed to initialize one-shot signing");
    }

    // Get the accumulated data from the digest context
    // For Ed25519/Ed448, we need to pass the original data, not a digest
    // Since we've been accumulating with DigestUpdate, we need to use the data buffer
    // Unfortunately, EVP_MD_CTX doesn't expose the accumulated data directly
    // We need to use EVP_DigestSign with the accumulated data

    // For one-shot variants, determine signature length first
    if (EVP_DigestSign(sign_ctx.get(), nullptr, &sig_len, data_buffer.data(), data_buffer.size()) <= 0) {
      throw std::runtime_error("Failed to determine Ed signature length");
    }

    sig_buf = std::make_unique<uint8_t[]>(sig_len);
    if (EVP_DigestSign(sign_ctx.get(), sig_buf.get(), &sig_len, data_buffer.data(), data_buffer.size()) <= 0) {
      unsigned long err = ERR_get_error();
      char err_buf[256];
      ERR_error_string_n(err, err_buf, sizeof(err_buf));
      throw std::runtime_error("Failed to sign with Ed key: " + std::string(err_buf));
    }
  } else {
    // Standard signing flow for RSA/ECDSA
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    if (EVP_DigestFinal_ex(md_ctx, digest, &digest_len) <= 0) {
      throw std::runtime_error("Failed to finalize digest");
    }

    EvpPkeyCtxPtr pkey_ctx{EVP_PKEY_CTX_new(pkey, nullptr), EVP_PKEY_CTX_free};
    if (!pkey_ctx) {
      throw std::runtime_error("Failed to create signing context");
    }

    if (EVP_PKEY_sign_init(pkey_ctx.get()) <= 0) {
      char err_buf[512];
      snprintf(err_buf, sizeof(err_buf), "Failed to initialize signing for key type %d (expected one-shot: %s, RNQC_HAS_ML_DSA=%d)",
               pkey_type, is_one_shot ? "true" : "false", RNQC_HAS_ML_DSA);
      throw std::runtime_error(std::string(err_buf) + ": " + getOpenSSLError());
    }

    if (padding.has_value()) {
      int pad = static_cast<int>(padding.value());
      if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx.get(), pad) <= 0) {
        throw std::runtime_error("Failed to set RSA padding");
      }
    }

    if (saltLength.has_value() && padding.has_value() && static_cast<int>(padding.value()) == RSA_PKCS1_PSS_PADDING) {
      int salt_len = static_cast<int>(saltLength.value());
      if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx.get(), salt_len) <= 0) {
        throw std::runtime_error("Failed to set PSS salt length");
      }
    }

    if (EVP_PKEY_CTX_set_signature_md(pkey_ctx.get(), md) <= 0) {
      throw std::runtime_error("Failed to set signature digest");
    }

    if (EVP_PKEY_sign(pkey_ctx.get(), nullptr, &sig_len, digest, digest_len) <= 0) {
      throw std::runtime_error("Failed to determine signature length");
    }

    sig_buf = std::make_unique<uint8_t[]>(sig_len);
    if (EVP_PKEY_sign(pkey_ctx.get(), sig_buf.get(), &sig_len, digest, digest_len) <= 0) {
      unsigned long err = ERR_get_error();
      char err_buf[256];
      ERR_error_string_n(err, err_buf, sizeof(err_buf));
      throw std::runtime_error("Failed to sign: " + std::string(err_buf));
    }
  }

  int dsa_enc = dsaEncoding.has_value() ? static_cast<int>(dsaEncoding.value()) : kSigEncDER;
  if (dsa_enc == kSigEncP1363) {
    unsigned int n = getBytesOfRS(pkey);
    if (n > 0) {
      auto p1363_buf = std::make_unique<uint8_t[]>(2 * n);
      std::memset(p1363_buf.get(), 0, 2 * n);
      if (convertSignatureToP1363(sig_buf.get(), sig_len, p1363_buf.get(), n)) {
        uint8_t* raw_ptr = p1363_buf.get();
        return std::make_shared<NativeArrayBuffer>(p1363_buf.release(), 2 * n, [raw_ptr]() { delete[] raw_ptr; });
      }
    }
  }

  uint8_t* raw_ptr = sig_buf.get();
  return std::make_shared<NativeArrayBuffer>(sig_buf.release(), sig_len, [raw_ptr]() { delete[] raw_ptr; });
}

} // namespace margelo::nitro::crypto
