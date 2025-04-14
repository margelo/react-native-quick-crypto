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

void HybridCipher::checkCtx() const {
  if (!ctx) {
    throw std::runtime_error("Cipher not initialized. Did you call setArgs()?");
  }
}

bool HybridCipher::maybePassAuthTagToOpenSSL() {
  if (auth_tag_state == kAuthTagKnown) {
    OSSL_PARAM params[] = {
      OSSL_PARAM_construct_octet_string(
        OSSL_CIPHER_PARAM_AEAD_TAG,
        auth_tag,
        auth_tag_len
      ),
      OSSL_PARAM_construct_end()
    };
    if (!EVP_CIPHER_CTX_set_params(ctx, params)) {
      unsigned long err = ERR_get_error();
      char err_buf[256];
      ERR_error_string_n(err, err_buf, sizeof(err_buf));
      return false;
    }
    auth_tag_state = kAuthTagPassedToOpenSSL;
  }
  return true;
}

void HybridCipher::init(
  const std::shared_ptr<ArrayBuffer> cipher_key,
  const std::shared_ptr<ArrayBuffer> iv
) {
  // Clean up any existing context
  if (ctx) {
    EVP_CIPHER_CTX_free(ctx);
    ctx = nullptr;
  }

  // 1. Get cipher implementation by name
  const EVP_CIPHER* cipher = EVP_get_cipherbyname(cipher_type.c_str());
  if (!cipher) {
    throw std::runtime_error("Unknown cipher " + cipher_type);
  }

  // 2. Create a new context
  ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    throw std::runtime_error("Failed to create cipher context");
  }

  // Initialise the encryption/decryption operation with the cipher type.
  // Key and IV will be set later by the derived class if needed.
  if (EVP_CipherInit_ex(ctx, cipher, nullptr, nullptr, nullptr, is_cipher) != 1) {
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    EVP_CIPHER_CTX_free(ctx);
    ctx = nullptr;
    throw std::runtime_error("HybridCipher: Failed initial CipherInit setup: " + std::string(err_buf));
  }

}

std::shared_ptr<ArrayBuffer>
HybridCipher::update(
  const std::shared_ptr<ArrayBuffer>& data
) {
  auto native_data = ToNativeArrayBuffer(data);
  checkCtx();
  size_t in_len = native_data->size();
  if (in_len > INT_MAX) {
    throw std::runtime_error("Message too long");
  }

  int out_len = in_len + EVP_CIPHER_CTX_block_size(ctx);
  uint8_t* out = new uint8_t[out_len];
  // Perform the cipher update operation. The real size of the output is
  // returned in out_len
  EVP_CipherUpdate(
    ctx,
    out,
    &out_len,
    native_data->data(),
    in_len
  );

  // Create and return a new buffer of exact size needed
  return std::make_shared<NativeArrayBuffer>(
    out,
    out_len,
    [=]() { delete[] out; }
  );
}

std::shared_ptr<ArrayBuffer>
HybridCipher::final() {
  checkCtx();
  int out_len = EVP_CIPHER_CTX_block_size(ctx);
  uint8_t* out = new uint8_t[out_len];
  EVP_CipherFinal_ex(
    ctx,
    out,
    &out_len
  );

  return std::make_shared<NativeArrayBuffer>(
    out,
    out_len,
    [=]() { delete[] out; }
  );
}

bool HybridCipher::setAAD(
  const std::shared_ptr<ArrayBuffer>& data,
  std::optional<double> plaintextLength
) {
  checkCtx();
  auto native_data = ToNativeArrayBuffer(data);

  // Set the AAD
  int out_len;
  if (!EVP_CipherUpdate(ctx, nullptr, &out_len, native_data->data(), native_data->size())) {
    return false;
  }

  has_aad = true;
  return true;
}

bool HybridCipher::setAutoPadding(
  bool autoPad
) {
  checkCtx();
  return EVP_CIPHER_CTX_set_padding(ctx, autoPad) == 1;
}

bool HybridCipher::setAuthTag(
  const std::shared_ptr<ArrayBuffer>& tag
) {
  checkCtx();
  if (is_cipher) {
    throw std::runtime_error("Auth tag cannot be set when encrypting");
  }

  auto native_tag = ToNativeArrayBuffer(tag);
  if (native_tag->size() < 4 || native_tag->size() > 16) {
    throw std::runtime_error("Invalid auth tag length. Must be between 4 and 16 bytes.");
  }

  // Store the auth tag for later verification
  auth_tag_len = native_tag->size();
  std::memcpy(auth_tag, native_tag->data(), auth_tag_len);
  auth_tag_state = kAuthTagKnown;

  return true;
}

std::shared_ptr<ArrayBuffer>
HybridCipher::getAuthTag() {
  checkCtx();
  if (!is_cipher) {
    throw std::runtime_error("Auth tag can only be retrieved in encryption mode");
  }

  if (auth_tag_state != kAuthTagKnown) {
    throw std::runtime_error("Auth tag not available. Call final() first.");
  }

  // Create a new buffer and copy the auth tag
  uint8_t* out = new uint8_t[auth_tag_len];
  std::memcpy(out, auth_tag, auth_tag_len);

  return std::make_shared<NativeArrayBuffer>(
    out,
    auth_tag_len,
    [=]() { delete[] out; }
  );
}

int HybridCipher::getMode() {
  if (!ctx) {
    throw std::runtime_error("Cipher not initialized. Did you call setArgs()?");
  }
  return EVP_CIPHER_CTX_get_mode(ctx);
}

void HybridCipher::setArgs(const CipherArgs& args) {
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
    this->auth_tag_len = kDefaultAuthTagLength;
  }
}

void collect_ciphers(EVP_CIPHER *cipher, void *arg) {
  auto ciphers = static_cast<std::vector<std::string>*>(arg);
  const char* name = EVP_CIPHER_get0_name(cipher);
  if (
    name != nullptr
    // TODO: implement SM4-CCM as it isn't working yet - for now exclude it
    && strcmp(name, "SM4-CCM") != 0
  ) {
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
