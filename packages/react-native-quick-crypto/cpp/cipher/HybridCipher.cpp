#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <string>
#include <vector>

#include "HybridCipher.hpp"
#include "Utils.hpp"

namespace margelo::nitro::crypto {

HybridCipher::~HybridCipher() {
  if (ctx) {
    EVP_CIPHER_CTX_free(ctx);
  }
}

constexpr unsigned kNoAuthTagLength = static_cast<unsigned>(-1);
constexpr unsigned kDefaultAuthTagLength = 16;  // Default tag length for OCB, SIV, CCM, ChaCha20-Poly1305

bool isSupportedAuthenticatedMode(const EVP_CIPHER *cipher) {
  int mode = EVP_CIPHER_mode(cipher);
  int nid = EVP_CIPHER_get_nid(cipher);

  switch (mode) {
    case EVP_CIPH_CCM_MODE:
    case EVP_CIPH_GCM_MODE:
#ifndef OPENSSL_NO_OCB
    case EVP_CIPH_OCB_MODE:
#endif
    case EVP_CIPH_SIV_MODE:
    case EVP_CIPH_GCM_SIV_MODE:
      return true;
    case EVP_CIPH_STREAM_CIPHER:
      return nid == NID_chacha20_poly1305;
    default:
      return false;
  }
}

bool isSupportedAuthenticatedMode(const EVP_CIPHER_CTX *ctx) {
  const EVP_CIPHER *cipher = EVP_CIPHER_CTX_cipher(ctx);
  return isSupportedAuthenticatedMode(cipher);
}

bool isValidAEADTagLength(unsigned int tag_len, int mode) {
  // OCB mode only supports tag lengths from 1 to 16 bytes
  if (mode == EVP_CIPH_OCB_MODE) {
    return tag_len >= 1 && tag_len <= 16;
  }
  // GCM mode supports 4, 8, or 12-16 bytes
  return tag_len == 4 || tag_len == 8 || (tag_len >= 12 && tag_len <= 16);
}


bool HybridCipher::maybePassAuthTagToOpenSSL() {
  if (auth_tag_state == kAuthTagKnown) {
    OSSL_PARAM params[] = {
      OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                       auth_tag,
                                       auth_tag_len),
      OSSL_PARAM_construct_end()
    };
    if (!EVP_CIPHER_CTX_set_params(ctx, params)) {
      return false;
    }
    auth_tag_state = kAuthTagPassedToOpenSSL;
  }
  return true;
}

bool HybridCipher::isAuthenticatedMode() const {
  // Check if this cipher operates in an AEAD mode that we support.
  return isSupportedAuthenticatedMode(ctx);
}

bool HybridCipher::setAuthTagLength(const char* mode_str) {
  OSSL_PARAM params[] = {
    OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN,
                              reinterpret_cast<size_t*>(&auth_tag_len)),
    OSSL_PARAM_construct_end()
  };

  if (!EVP_CIPHER_CTX_set_params(ctx, params)) {
    throw std::runtime_error(std::string("Failed to set tag length for ") + mode_str + ": " +
      std::string(ERR_reason_error_string(ERR_get_error())));
    return false;
  }
  return true;
}

bool HybridCipher::initGCMMode() {
  if (auth_tag_len == kNoAuthTagLength) {
    auth_tag_len = kDefaultAuthTagLength;  // Default for GCM
  }
  if (!isValidAEADTagLength(auth_tag_len, EVP_CIPH_GCM_MODE)) {
    throw std::runtime_error("Invalid authentication tag length (GCM)");
  }
  return setAuthTagLength("GCM");
}

bool HybridCipher::initOCBMode(const std::shared_ptr<NativeArrayBuffer>& native_iv) {
  if (auth_tag_len == kNoAuthTagLength) {
    auth_tag_len = kDefaultAuthTagLength;  // Default for OCB
  }
  if (!isValidAEADTagLength(auth_tag_len, EVP_CIPH_OCB_MODE)) {
    throw std::runtime_error("Invalid authentication tag length (OCB)");
  }

  if (native_iv->size() > 15) {
    throw std::runtime_error("Invalid IV length for OCB mode (should be max 15 bytes)");
  }

  return setAuthTagLength("OCB");
}

bool HybridCipher::initSIVMode() {
  if (auth_tag_len == kNoAuthTagLength) {
    auth_tag_len = kDefaultAuthTagLength;  // Default for SIV
  }
  if (!isValidAEADTagLength(auth_tag_len, EVP_CIPH_SIV_MODE)) {
    throw std::runtime_error("Invalid authentication tag length (SIV)");
  }
  return setAuthTagLength("SIV");
}

bool HybridCipher::initGCMSIVMode() {
  if (auth_tag_len == kNoAuthTagLength) {
    auth_tag_len = kDefaultAuthTagLength;  // Default for GCM-SIV
  }
  if (!isValidAEADTagLength(auth_tag_len, EVP_CIPH_GCM_MODE)) { // Use GCM tag length validation
    throw std::runtime_error("Invalid authentication tag length (GCM-SIV)");
  }
  return setAuthTagLength("GCM-SIV");
}

bool HybridCipher::initChaCha20Poly1305() {
  if (auth_tag_len == kNoAuthTagLength) {
    auth_tag_len = kDefaultAuthTagLength;  // Default for ChaCha20-Poly1305
  }
  return setAuthTagLength("ChaCha20-Poly1305");
}

bool HybridCipher::initCCMMode(
  int iv_len,
  const std::shared_ptr<NativeArrayBuffer>& native_iv
) {
  if (native_iv->size() < 7 || native_iv->size() > 13) {
    throw std::runtime_error("Invalid IV length for CCM mode (should be between 7 and 13 bytes)");
  }

  // Set IV length
  OSSL_PARAM iv_params[] = {
    OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_IVLEN, &iv_len),
    OSSL_PARAM_construct_end()
  };
  if (!EVP_CIPHER_CTX_set_params(ctx, iv_params)) {
    throw std::runtime_error("Invalid Cipher IV: " +
      std::string(ERR_reason_error_string(ERR_get_error())));
    return false;
  }

  // Check FIPS mode compatibility
  if (!is_cipher && EVP_default_properties_is_fips_enabled(nullptr)) {
    throw std::runtime_error("CCM encryption not supported in FIPS mode");
    return false;
  }

  // Set default tag length if not specified
  if (auth_tag_len == kNoAuthTagLength) {
    auth_tag_len = kDefaultAuthTagLength;  // Default for CCM
  }

  if (!setAuthTagLength("CCM")) {
    return false;
  }

  // Set message size limits based on IV length
  if (iv_len < 7 || iv_len > 13) {
    throw std::runtime_error("Invalid IV length (should be between 7 and 13 bytes)");
  }
  max_message_size = INT_MAX;
  if (iv_len == 12) max_message_size = 16777215;
  if (iv_len == 13) max_message_size = 65535;

  return true;
}

bool HybridCipher::initAuthenticated(
  const char *cipher_type,
  int iv_len,
  unsigned int auth_tag_len,
  const std::shared_ptr<NativeArrayBuffer>& native_iv
) {
  if (!isAuthenticatedMode()) {
    throw std::runtime_error("Cannot initialize unauthenticated cipher");
    return false;
  }

  const int mode = getMode();
  switch (mode) {
    case EVP_CIPH_GCM_MODE:
      return initGCMMode();
    case EVP_CIPH_OCB_MODE:
      return initOCBMode(native_iv);
    case EVP_CIPH_SIV_MODE:
      return initSIVMode();
    case EVP_CIPH_GCM_SIV_MODE:
      return initGCMSIVMode();
    case EVP_CIPH_CCM_MODE:
      return initCCMMode(iv_len, native_iv);
    default:
      if (EVP_CIPHER_CTX_nid(ctx) == NID_chacha20_poly1305) {
        return initChaCha20Poly1305();
      }
      throw std::runtime_error("Unsupported cipher mode");
      return false;
  }
}

bool HybridCipher::checkCCMMessageLength(int message_len) {
  if (getMode() != EVP_CIPH_CCM_MODE) {
    throw std::runtime_error("CCM encryption not supported in this mode");
  }
  if (message_len > max_message_size) {
    throw std::runtime_error("Message too long");
  }
  return true;
}

void
HybridCipher::init(
  const std::shared_ptr<ArrayBuffer> cipher_key,
  const std::shared_ptr<ArrayBuffer> iv
) {
  auto native_key = ToNativeArrayBuffer(cipher_key);
  auto native_iv = ToNativeArrayBuffer(iv);
  // fetch cipher
  EVP_CIPHER *cipher = EVP_CIPHER_fetch(
    nullptr,
    cipher_type.c_str(),
    nullptr
  );
  if (cipher == nullptr) {
    throw std::runtime_error("Invalid Cipher Algorithm: " + cipher_type);
  }

  // Create cipher context
  EVP_CIPHER_CTX_free(ctx);
  ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    EVP_CIPHER_free(cipher);
    throw std::runtime_error("Failed to create cipher context");
  }

  // Reset state
  has_aad = false;
  pending_auth_failed = false;
  auth_tag_state = kAuthTagUnknown;
  auth_tag_len = kNoAuthTagLength;

  // Get cipher mode
  int mode = EVP_CIPHER_get_mode(cipher);

  if (mode == EVP_CIPH_WRAP_MODE) {
    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
  }

  // Initialize blank context
  // because some algos need to set things before real initialization
  if (EVP_CipherInit_ex2(
    ctx,
    cipher,
    nullptr,
    nullptr,
    is_cipher ? 1 : 0,
    nullptr
  ) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    ctx = nullptr;
    throw std::runtime_error("Failed to initialize blank cipher operation: " +
      std::string(ERR_reason_error_string(ERR_get_error())));
  }

  // For authenticated modes, initialize them
  if (isSupportedAuthenticatedMode(cipher)) {
    int iv_len;
    if (mode == EVP_CIPH_CCM_MODE) {
      iv_len = static_cast<int>(native_iv->size());
    } else {
      iv_len = EVP_CIPHER_iv_length(cipher);
    }
    if (iv_len < 0) {
      EVP_CIPHER_CTX_free(ctx);
      EVP_CIPHER_free(cipher);
      ctx = nullptr;
      throw std::runtime_error("Invalid Cipher IV length");
    }
    if (!initAuthenticated(cipher_type.c_str(), iv_len, auth_tag_len, native_iv)) {
      EVP_CIPHER_CTX_free(ctx);
      EVP_CIPHER_free(cipher);
      ctx = nullptr;
      throw std::runtime_error("Failed to initialize authenticated mode");
    }
  }

  // Initialize cipher context
  if (EVP_CipherInit_ex2(
    ctx,
    cipher,
    native_key->data(),
    native_iv->data(),
    is_cipher ? 1 : 0,
    nullptr
  ) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    ctx = nullptr;
    throw std::runtime_error("Failed to initialize cipher operation: " +
      std::string(ERR_reason_error_string(ERR_get_error())));
  }

  // we've set up the context, free the cipher
  EVP_CIPHER_free(cipher);
}

std::shared_ptr<ArrayBuffer>
HybridCipher::update(
  const std::shared_ptr<ArrayBuffer>& data
) {
  auto native_data = ToNativeArrayBuffer(data);
  if (!ctx) {
    throw std::runtime_error("Cipher not initialized. Did you call setArgs()?");
  }

  size_t in_len = native_data->size();
  if (in_len > INT_MAX) {
    throw std::runtime_error("Message too long");
  }

  // For decryption in authenticated modes, we need to set the expected tag length
  if (!is_cipher && isAuthenticatedMode()) {
    maybePassAuthTagToOpenSSL();
  }

  auto mode = getMode();
  int out_len = in_len + EVP_CIPHER_CTX_block_size(ctx);
  // For key wrapping algorithms, get output size by calling
  // EVP_CipherUpdate() with null output.
  if (is_cipher && mode == EVP_CIPH_WRAP_MODE) {
    if (EVP_CipherUpdate(
        ctx,
        nullptr,
        &out_len,
        native_data->data(),
        native_data->size()
      ) != 1) {
      throw std::runtime_error("Failed to get output size for wrapping algorithm");
    }
  }

  // Create output buffer for the operation
  uint8_t* out = new uint8_t[out_len];

  // For CCM mode without AAD, we need to set the message length before the first update
  if (mode == EVP_CIPH_CCM_MODE && !is_cipher && !has_aad) {
    if (!EVP_CipherUpdate(ctx, nullptr, &out_len, nullptr, in_len)) {
      throw std::runtime_error("Failed to set CCM message length");
    }
  }

  // Perform the cipher update operation. The real size of the output is
  // returned in out_len
  bool ok = EVP_CipherUpdate(
    ctx,
    out,
    &out_len,
    native_data->data(),
    in_len
  ) == 1;

  // When in CCM mode, EVP_CipherUpdate will fail if the authentication tag
  // is invalid. In that case, remember the error and throw in final().
  if (!ok && !is_cipher && mode == EVP_CIPH_CCM_MODE) {
    pending_auth_failed = true;
  }

  // Create and return a new buffer of exact size needed
  return std::make_shared<NativeArrayBuffer>(
    out,
    out_len,
    [=]() { delete[] out; }
  );
}

std::shared_ptr<ArrayBuffer>
HybridCipher::final() {
  if (!ctx) {
    throw std::runtime_error("Cipher not initialized. Did you call setArgs()?");
  }

  int mode = getMode();
  int out_len = EVP_CIPHER_CTX_block_size(ctx);
  uint8_t* out = new uint8_t[out_len];

  if (!is_cipher && isSupportedAuthenticatedMode(ctx)) {
    maybePassAuthTagToOpenSSL();
  }

  bool ok;

  // In CCM mode, final() only checks whether authentication failed in
  // update(). EVP_CipherFinal_ex must not be called and will fail.
  if (!is_cipher && mode == EVP_CIPH_CCM_MODE) {
      ok = !pending_auth_failed;
      out = new uint8_t[0];
  } else {
    ok = EVP_CipherFinal_ex(
      ctx,
      out,
      &out_len
    ) == 1;

    // Additional operations for authenticated modes
    if (ok && is_cipher && isAuthenticatedMode() && mode != EVP_CIPH_CCM_MODE) {
      // For CCM mode, the tag is included in the final output
      // For other AEAD modes (GCM, OCB, SIV), get the tag explicitly
      if ((mode == EVP_CIPH_OCB_MODE || mode == EVP_CIPH_SIV_MODE) && auth_tag_len == kNoAuthTagLength) {
        // For OCB and SIV modes, if no tag length was specified, use 16 bytes
        auth_tag_len = 16;
      }

      // Zero out auth_tag before getting new tag
      std::memset(auth_tag, 0, EVP_GCM_TLS_TAG_LEN);

      OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                          auth_tag,
                                          auth_tag_len),
        OSSL_PARAM_construct_end()
      };
      if (!EVP_CIPHER_CTX_get_params(ctx, params)) {
        delete[] out;
        throw std::runtime_error("Failed to get authentication tag: "
          + std::string(ERR_reason_error_string(ERR_get_error())));
      }
      auth_tag_state = kAuthTagKnown;
    }
  }

  // Create and return a new buffer of exact size needed
  return std::make_shared<NativeArrayBuffer>(
    out,
    out_len,
    [=]() { delete[] out; }
  );
}

bool
HybridCipher::setAAD(
  const std::shared_ptr<ArrayBuffer>& data,
  std::optional<double> plaintextLength
) {
  auto native_data = ToNativeArrayBuffer(data);
  if (!ctx || !isAuthenticatedMode()) {
    return false;
  }

  int out_len;
  int mode = getMode();

  // When in CCM mode, we need to set the authentication tag and the plaintext
  // length in advance.
  if (mode == EVP_CIPH_CCM_MODE) {
    if (!plaintextLength.has_value() || plaintextLength.value() < 0) {
      throw std::runtime_error("plaintextLength > 0 required for CCM mode with AAD");
    }
    int plaintext_len = static_cast<int>(plaintextLength.value());
    if (!checkCCMMessageLength(plaintext_len)) {
      return false;
    }

    if (!is_cipher) {
      if (!maybePassAuthTagToOpenSSL()) {
        return false;
      }
    }

    if (!EVP_CipherUpdate(ctx, nullptr, &out_len, nullptr, plaintext_len)) {
      throw std::runtime_error("Failed to set message length");
    }
    has_aad = true;
  }

  return EVP_CipherUpdate(ctx, nullptr, &out_len, native_data->data(), native_data->size()) == 1;
}

bool
HybridCipher::setAutoPadding(
  bool autoPad
) {
  if (!ctx) {
    throw std::runtime_error("Cipher not initialized. Did you call setArgs()?");
  }

  return EVP_CIPHER_CTX_set_padding(ctx, autoPad) == 1;
}

bool
HybridCipher::setAuthTag(
  const std::shared_ptr<ArrayBuffer>& tag
) {
  if (!ctx || !isAuthenticatedMode() || is_cipher || auth_tag_state != kAuthTagUnknown) {
    return false;
  }

  // Copy the tag into our internal buffer
  auto native_tag = ToNativeArrayBuffer(tag);
  size_t tag_size = native_tag->size();
  if (tag_size > EVP_GCM_TLS_TAG_LEN) {
    throw std::runtime_error("Authentication tag is too long");
  }
  std::memset(auth_tag, 0, EVP_GCM_TLS_TAG_LEN);
  std::memcpy(auth_tag, native_tag->data(), tag_size);
  auth_tag_len = tag_size;
  auth_tag_state = kAuthTagKnown;

  return true;
}

std::shared_ptr<ArrayBuffer>
HybridCipher::getAuthTag() {
  if (!ctx) {
    throw std::runtime_error("Cannot getAuthTag while encryption is in progress");
  }
  if (!is_cipher) {
    throw std::runtime_error("Cannot getAuthTag in decryption mode");
  }
  if (auth_tag_len == kNoAuthTagLength) {
    throw std::runtime_error(
      "No authentication tag is set.  Make sure to call final() before getting the auth tag."
    );
  }

  // Create a new buffer and copy the auth tag data
  uint8_t* out = new uint8_t[auth_tag_len];
  std::memcpy(out, auth_tag, auth_tag_len);

  // Create and return a new buffer with proper cleanup
  return std::make_shared<NativeArrayBuffer>(
    out,
    auth_tag_len,
    [=]() { delete[] out; }
  );
}

int
HybridCipher::getMode() {
  if (!ctx) {
    throw std::runtime_error("Cipher not initialized. Did you call setArgs()?");
  }
  return EVP_CIPHER_CTX_get_mode(ctx);
}

void
HybridCipher::setArgs(
  const CipherArgs& args
) {
  this->is_cipher = args.isCipher;
  this->cipher_type = args.cipherType;

  // Reset auth tag state
  auth_tag_state = kAuthTagUnknown;
  std::memset(auth_tag, 0, EVP_GCM_TLS_TAG_LEN);

  // Set auth tag length from args or use default
  if (args.authTagLen.has_value()) {
    if (!CheckIsUint32(args.authTagLen.value())) {
      throw std::runtime_error("authTagLen must be uint32");
    }
    uint32_t requested_len = static_cast<uint32_t>(args.authTagLen.value());
    if (requested_len > EVP_GCM_TLS_TAG_LEN) {
      throw std::runtime_error("Authentication tag length too large");
    }
    this->auth_tag_len = requested_len;
  } else {
    // Default to 16 bytes for all authenticated modes
    this->auth_tag_len = 16;
  }

  init(
    args.cipherKey,
    args.iv
  );
}

void collect_ciphers(EVP_CIPHER *cipher, void *arg) {
  auto ciphers = static_cast<std::vector<std::string>*>(arg);
  const char* name = EVP_CIPHER_get0_name(cipher);
  if (name != nullptr) {
    ciphers->push_back(name);
  }
}

std::vector<std::string>
HybridCipher::getSupportedCiphers() {
  std::vector<std::string> ciphers;

  EVP_CIPHER_do_all_provided(
    nullptr, // nullptr is default library context
    collect_ciphers,
    &ciphers
  );

  return ciphers;
}

} // namespace margelo::nitro::crypto
