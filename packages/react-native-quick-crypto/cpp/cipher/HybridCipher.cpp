#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
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

bool isSupportedAuthenticatedMode(const EVP_CIPHER *cipher) {
  switch (EVP_CIPHER_mode(cipher)) {
    case EVP_CIPH_CCM_MODE:
    case EVP_CIPH_GCM_MODE:
#ifndef OPENSSL_NO_OCB
    case EVP_CIPH_OCB_MODE:
#endif
      return true;
    case EVP_CIPH_STREAM_CIPHER:
      return EVP_CIPHER_get_nid(cipher) == NID_chacha20_poly1305;
    default:
      return false;
  }
}

bool isSupportedAuthenticatedMode(const EVP_CIPHER_CTX *ctx) {
  const EVP_CIPHER *cipher = EVP_CIPHER_CTX_cipher(ctx);
  return isSupportedAuthenticatedMode(cipher);
}

bool isValidGCMTagLength(unsigned int tag_len) {
  return tag_len == 4 || tag_len == 8 || (tag_len >= 12 && tag_len <= 16);
}


bool HybridCipher::maybePassAuthTagToOpenSSL() {
  if (auth_tag_state == kAuthTagKnown) {
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, auth_tag_len,
                             reinterpret_cast<unsigned char *>(auth_tag))) {
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

bool HybridCipher::initAuthenticated(
  const char *cipher_type,
  int iv_len,
  unsigned int auth_tag_len
) {
  if (!isAuthenticatedMode()) {
    throw std::runtime_error("Cannot initialize unauthenticated cipher");
    return false;
  }

  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv_len, nullptr)) {
    throw std::runtime_error("Invalid Cipher IV");
    return false;
  }

  const int mode = getMode();

  if (mode == EVP_CIPH_GCM_MODE) {
    if (auth_tag_len != kNoAuthTagLength) {
      if (!isValidGCMTagLength(auth_tag_len)) {
        throw std::runtime_error("Invalid authentication tag length (GCM)");
      }

      // Remember the given authentication tag length for later.
      this->auth_tag_len = auth_tag_len;
    }
  } else {
    if (auth_tag_len == kNoAuthTagLength) {
      // We treat ChaCha20-Poly1305 special. Like GCM, the authentication tag
      // length defaults to 16 bytes when encrypting. Unlike GCM, the
      // authentication tag length also defaults to 16 bytes when decrypting,
      // whereas GCM would accept any valid authentication tag length.
      if (EVP_CIPHER_CTX_nid(ctx) == NID_chacha20_poly1305) {
        auth_tag_len = 16;
      } else {
        throw std::runtime_error("Invalid authentication tag length (default)");
        return false;
      }
    }

    if (
      mode == EVP_CIPH_CCM_MODE && !is_cipher &&
      EVP_default_properties_is_fips_enabled(nullptr)
    ) {
      throw std::runtime_error("CCM encryption not supported in FIPS mode");
      return false;
    }

    // Tell OpenSSL about the desired length.
    if (
      !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, auth_tag_len, nullptr)
    ) {
      throw std::runtime_error("Invalid authentication tag length");
      return false;
    }

    // Remember the given authentication tag length for later.
    this->auth_tag_len = auth_tag_len;

    if (mode == EVP_CIPH_CCM_MODE) {
      // Restrict the message length to min(INT_MAX, 2^(8*(15-iv_len))-1) bytes.
      if (iv_len < 7 || iv_len > 13) {
        throw std::runtime_error("Invalid IV length (should be between 7 and 13 bytes)");
      }
      max_message_size = INT_MAX;
      if (iv_len == 12) max_message_size = 16777215;
      if (iv_len == 13) max_message_size = 65535;
    }
  }

  return true;
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
  ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    EVP_CIPHER_free(cipher);
    throw std::runtime_error("Failed to create cipher context");
  }

  // Initialize cipher operation
  if (
    EVP_CipherInit_ex2(
      ctx,
      cipher,
      cipher_key->data(),
      iv->data(),
      is_cipher ? 1 : 0,
      nullptr
    ) != 1
  ) {
    // TODO: wrap these three calls into a macro?
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    ctx = nullptr;
    throw std::runtime_error("Failed to initialize cipher operation: " +
      std::to_string(ERR_get_error()));
  }

  // check authenticated mode
  int iv_len = EVP_CIPHER_iv_length(cipher);
  if (isSupportedAuthenticatedMode(cipher)) {
    if (iv_len < 0) {
      EVP_CIPHER_CTX_free(ctx);
      EVP_CIPHER_free(cipher);
      ctx = nullptr;
      throw std::runtime_error("Invalid Cipher IV length");
    }
    if (!initAuthenticated(cipher_type.c_str(), iv_len, auth_tag_len)) {
      EVP_CIPHER_CTX_free(ctx);
      EVP_CIPHER_free(cipher);
      ctx = nullptr;
      throw std::runtime_error("Failed to initialize authenticated mode");
    }
  }

  // we've set up the context, free the cipher
  EVP_CIPHER_free(cipher);
}

std::shared_ptr<ArrayBuffer>
HybridCipher::update(
  const std::shared_ptr<ArrayBuffer>& data
) {
  if (!ctx) {
    throw std::runtime_error("Cipher not initialized. Did you call setArgs()?");
  }

  // Calculate the maximum output length
  int outLen = data->size() + EVP_MAX_BLOCK_LENGTH;
  int updateLen = 0;

  // Create a temporary buffer for the operation
  unsigned char* tempBuf = new unsigned char[outLen];

  auto mode = getMode();
  if (mode == EVP_CIPH_CCM_MODE && !checkCCMMessageLength(data->size())) {
    delete[] tempBuf;
    throw std::runtime_error("Invalid message size for CCM");
  }

  // Pass the authentication tag to OpenSSL if possible. This will only
  // happen once, usually on the first update.
  if (!is_cipher && isAuthenticatedMode()) {
    maybePassAuthTagToOpenSSL();
  }

  // Perform the cipher update operation
  if (
    EVP_CipherUpdate(
      ctx,
      tempBuf,
      &updateLen,
      reinterpret_cast<const unsigned char*>(data->data()),
      data->size()
    ) != 1
  ) {
    delete[] tempBuf;
    throw std::runtime_error("Failed to update cipher");
  }

  // Create and return a new buffer of exact size needed
  return std::make_shared<NativeArrayBuffer>(
    tempBuf,
    updateLen,
    [=]() { delete[] tempBuf; }
  );
}

std::shared_ptr<ArrayBuffer>
HybridCipher::final() {
  if (!ctx) {
    throw std::runtime_error("Cipher not initialized. Did you call setArgs()?");
  }

  int finalLen = 0;
  uint8_t* tempBuf = new uint8_t[EVP_MAX_BLOCK_LENGTH];

  // Finalize the encryption/decryption
  if (EVP_CipherFinal_ex(
        ctx,
        tempBuf,
        &finalLen) != 1) {
    delete[] tempBuf;
    throw std::runtime_error("Failed to finalize cipher: " +
      std::to_string(ERR_get_error()));
  }

  // Create and return a new buffer of exact size needed
  return std::make_shared<NativeArrayBuffer>(
    tempBuf,
    finalLen,
    [=]() { delete[] tempBuf; }
  );
}

bool
HybridCipher::setAAD(
  const std::shared_ptr<ArrayBuffer>& data,
  std::optional<double> plaintextLength
) {
  return false;
}

bool
HybridCipher::setAutoPadding(
  bool autoPad
) {
  return false;
}

bool
HybridCipher::setAuthTag(
  const std::shared_ptr<ArrayBuffer>& tag
) {
  return false;
}

std::shared_ptr<ArrayBuffer>
HybridCipher::getAuthTag() {
  return nullptr;
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
  if (args.authTagLen.has_value()) {
    if (!CheckIsUint32(args.authTagLen.value())) {
      throw std::runtime_error("authTagLen must be uint32");
    }
    this->auth_tag_len = static_cast<uint32_t>(args.authTagLen.value());
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
