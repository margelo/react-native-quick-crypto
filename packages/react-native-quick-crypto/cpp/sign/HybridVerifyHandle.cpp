#include "HybridVerifyHandle.hpp"

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

HybridVerifyHandle::~HybridVerifyHandle() {
  if (md_ctx) {
    EVP_MD_CTX_free(md_ctx);
    md_ctx = nullptr;
  }
}

void HybridVerifyHandle::init(const std::string& algorithm) {
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

void HybridVerifyHandle::update(const std::shared_ptr<ArrayBuffer>& data) {
  if (!md_ctx) {
    throw std::runtime_error("Verify not initialized");
  }

  // Accumulate raw data for potential one-shot verification (Ed25519/Ed448/ML-DSA)
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

// Check if key type requires one-shot verification (Ed25519, Ed448, ML-DSA)
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
// transitively owns its EVP_PKEY_CTX after a successful EVP_DigestVerifyInit,
// so we deliberately rely on EVP_MD_CTX_free to clean both up; the standalone
// EvpPkeyCtxPtr alias is kept only for the RSA/ECDSA branch, where we
// allocate the PKEY_CTX directly via EVP_PKEY_CTX_new.
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

bool HybridVerifyHandle::verify(const std::shared_ptr<HybridKeyObjectHandleSpec>& keyHandle, const std::shared_ptr<ArrayBuffer>& signature,
                                std::optional<double> padding, std::optional<double> saltLength, std::optional<double> dsaEncoding) {
  if (!md_ctx) {
    throw std::runtime_error("Verify not initialized");
  }

  auto keyHandleImpl = std::static_pointer_cast<HybridKeyObjectHandle>(keyHandle);
  EVP_PKEY* pkey = keyHandleImpl->getKeyObjectData().GetAsymmetricKey().get();

  if (!pkey) {
    throw std::runtime_error("Invalid public key for verification");
  }

  const unsigned char* sig_data = signature->data();
  size_t sig_len = signature->size();

  // Ed25519/Ed448/ML-DSA require one-shot verification with EVP_DigestVerify
  // Also use one-shot path if no digest was specified (md == nullptr)
  if (isOneShotVariant(pkey) || md == nullptr) {
    EvpMdCtxPtr verify_ctx{EVP_MD_CTX_new(), EVP_MD_CTX_free};
    if (!verify_ctx) {
      throw std::runtime_error("Failed to create verification context");
    }

    // Let OpenSSL allocate the PKEY_CTX from the key's keymgmt. On success the
    // EVP_MD_CTX assumes ownership and EVP_MD_CTX_free will dispose it; on
    // failure pkey_ctx_raw stays nullptr, so there is nothing to leak. This
    // mirrors ncrypto's EVPMDCtxPointer::verifyInit (Node.js deps/ncrypto/ncrypto.cc
    // and ~/dev/ncrypto/src/ncrypto.cpp), which works for RSA, ECDSA, Ed25519,
    // Ed448 and ML-DSA without any algorithm-name pre-creation.
    EVP_PKEY_CTX* pkey_ctx_raw = nullptr;
    if (EVP_DigestVerifyInit(verify_ctx.get(), &pkey_ctx_raw, nullptr, nullptr, pkey) <= 0) {
      throw std::runtime_error("Failed to initialize one-shot verification");
    }

    int result = EVP_DigestVerify(verify_ctx.get(), sig_data, sig_len, data_buffer.data(), data_buffer.size());
    return result == 1;
  }

  // Standard verification flow for RSA/ECDSA
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int digest_len = 0;

  if (EVP_DigestFinal_ex(md_ctx, digest, &digest_len) <= 0) {
    throw std::runtime_error("Failed to finalize digest");
  }

  std::unique_ptr<uint8_t[]> der_sig_buf;
  int dsa_enc = dsaEncoding.has_value() ? static_cast<int>(dsaEncoding.value()) : kSigEncDER;
  if (dsa_enc == kSigEncP1363) {
    unsigned int n = getBytesOfRS(pkey);
    if (n > 0) {
      size_t der_len = 0;
      der_sig_buf = convertSignatureToDER(sig_data, sig_len, n, &der_len);
      if (der_sig_buf) {
        sig_data = der_sig_buf.get();
        sig_len = der_len;
      }
    }
  }

  EvpPkeyCtxPtr pkey_ctx{EVP_PKEY_CTX_new(pkey, nullptr), EVP_PKEY_CTX_free};
  if (!pkey_ctx) {
    throw std::runtime_error("Failed to create verification context");
  }

  if (EVP_PKEY_verify_init(pkey_ctx.get()) <= 0) {
    throw std::runtime_error("Failed to initialize verification");
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

  int result = EVP_PKEY_verify(pkey_ctx.get(), sig_data, sig_len, digest, digest_len);
  return result == 1;
}

} // namespace margelo::nitro::crypto
