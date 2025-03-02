#include <stdexcept>
#include "CCMCipher.hpp"
#include "Utils.hpp"

namespace margelo::nitro::crypto {

/**
 * playground to test raw OpenSSL API calls for mode
 */
void CCMCipher::raw(
  const std::shared_ptr<ArrayBuffer> cipher_key,
  const std::shared_ptr<ArrayBuffer> iv
) {

  // init context ==============================================================

  // context
  if (ctx) {
    EVP_CIPHER_CTX_reset(ctx);
  }
  ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    throw std::runtime_error("Failed to create cipher context");
  }

  // cipher
  EVP_CIPHER* cipher = EVP_CIPHER_fetch(nullptr, cipher_type.c_str(), nullptr);
  if (!cipher) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("Invalid cipher type: " + cipher_type);
  }

  auto native_key = ToNativeArrayBuffer(cipher_key);
  auto native_iv = ToNativeArrayBuffer(iv);

  // init
  if (!EVP_CipherInit_ex2(
    ctx,
    cipher,
    native_key->data(),
    native_iv->data(),
    is_cipher ? 1 : 0,
    nullptr
  )) {
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    ctx = nullptr;
    throw std::runtime_error("Failed to initialize cipher operation: " +
      std::string(ERR_reason_error_string(ERR_get_error())));
  }

  // cleanup from init
  EVP_CIPHER_free(cipher);

  // update ====================================================================

  // data to update
  std::string raw = "32|RmVZZkFUVmpRRkp0TmJaUm56ZU9qcnJkaXNNWVNpTTU*|iXmckfRWZB"
    "GWWELweCBsThSsfUHLeRe0KCsK8ooHgxie0zOINpXxfZi/oNG7uq9JWFVCk70gfzQH8ZUJjAfa"
    "Fg**";
  const uint8_t* in = reinterpret_cast<const uint8_t*>(raw.c_str());
  size_t in_len = raw.size();
  int out_len = 0;

  // CCM requires the plaintext length to be specified before the update
  if (!EVP_CipherUpdate(ctx, nullptr, &out_len, nullptr, in_len)) {
    EVP_CIPHER_CTX_free(ctx);
    ctx = nullptr;
    throw std::runtime_error("Failed to update cipher (set length): " +
      std::string(ERR_reason_error_string(ERR_get_error())));
  }

  // actual update operation
  uint8_t* out = new uint8_t[out_len];
  if (!EVP_CipherUpdate(ctx, out, &out_len, in, in_len)) {
    EVP_CIPHER_CTX_free(ctx);
    ctx = nullptr;
    throw std::runtime_error("Failed to update cipher (operation): " +
      std::string(ERR_reason_error_string(ERR_get_error())));
  }

  // final =====================================================================
}

// void CCMCipher::init(
//     const std::shared_ptr<ArrayBuffer> cipher_key,
//     const std::shared_ptr<ArrayBuffer> iv
// ) {
//   raw(cipher_key, iv);
// }

std::shared_ptr<ArrayBuffer> CCMCipher::update(const std::shared_ptr<ArrayBuffer>& data) {
  checkCtx();

  auto native_data = ToNativeArrayBuffer(data);
  size_t in_len = native_data->size();
  if (in_len < 0 || in_len > INT_MAX) {
    throw std::runtime_error("Invalid message length");
  }
  int out_len = 0;

  // Pass the authentication tag to OpenSSL if possible. This will only happen
  // once, usually on the first update.
  if (!is_cipher) {
    maybePassAuthTagToOpenSSL();
  }

  // CCM requires the plaintext length to be specified before the update
  if (!EVP_CipherUpdate(ctx, nullptr, &out_len, nullptr, in_len)) {
    throw std::runtime_error("Error in update() setting plaintext length: " +
      std::string(ERR_reason_error_string(ERR_get_error())));
  }

  uint8_t* out = new uint8_t[out_len];
  const uint8_t* in = reinterpret_cast<const uint8_t*>(native_data->data());

  // actual update operation
  if (!EVP_CipherUpdate(ctx, out, &out_len, in, in_len)) {
    pending_auth_failed = true;
    throw std::runtime_error("Error in update() doing operation: " +
      std::string(ERR_reason_error_string(ERR_get_error())));
  }

  return std::make_shared<NativeArrayBuffer>(
    out,
    out_len,
    [=]() { delete[] out; }
  );
}

std::shared_ptr<ArrayBuffer> CCMCipher::final() {
  checkCtx();

  // CCM final() returns block-size buffer, all work was done in update()
  int out_len = EVP_CIPHER_CTX_block_size(ctx);
  uint8_t* out = new uint8_t[out_len];

  // For CCM mode in encryption, get the tag after finalization
  if (is_cipher) {
    if (auth_tag_len == 0) {
      auth_tag_len = sizeof(auth_tag);
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, auth_tag_len, auth_tag)) {
      throw std::runtime_error("Failed to get auth tag: " +
        std::string(ERR_reason_error_string(ERR_get_error())));
    }
    auth_tag_state = kAuthTagKnown;
  }

  return std::make_shared<NativeArrayBuffer>(
    out,
    out_len,
    [=]() { delete[] out; }
  );
}

bool CCMCipher::setAAD(const std::shared_ptr<ArrayBuffer>& data, std::optional<double> plaintextLength) {
  checkCtx();

  if (!plaintextLength.has_value()) {
    throw std::runtime_error("CCM mode requires plaintextLength to be set");
  }

  // For CCM mode, we must set the total plaintext length before processing AAD
  int plaintext_len = static_cast<int>(plaintextLength.value());
  if (plaintext_len > kMaxMessageSize) {
    return false;
  }

  if (!is_cipher) {
    if (!maybePassAuthTagToOpenSSL()) {
      return false;
    }
  }

  // specify the plaintext length
  int out_len = 0;
  if (!EVP_CipherUpdate(ctx, nullptr, &out_len, nullptr, plaintext_len)) {
    return false;
  }

  // Process AAD if present
  auto native_data = ToNativeArrayBuffer(data);
  if (native_data->size() < 0) {
    return false;
  }
  // we must pass nullptr as the output buffer when processing AAD
  if (!EVP_CipherUpdate(ctx, nullptr, &out_len, native_data->data(), native_data->size())) {
    return false;
    // throw std::runtime_error("Failed to process AAD");
  }

  has_aad = true;
  return true;
}

// bool CCMCipher::setAuthTag(const std::shared_ptr<ArrayBuffer>& tag) {
//   checkCtx();
//   if (is_cipher) {
//     throw std::runtime_error("Auth tag cannot be set when encrypting");
//   }

//   auto native_tag = ToNativeArrayBuffer(tag);
//   if (native_tag->size() < 4 || native_tag->size() > 16) {
//     throw std::runtime_error("Invalid auth tag length. Must be between 4 and 16 bytes.");
//   }

//   // For CCM mode, we need to set the tag using EVP_CTRL_AEAD_SET_TAG
//   if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, native_tag->size(), const_cast<uint8_t*>(native_tag->data()))) {
//     throw std::runtime_error("Failed to set auth tag");
//   }

//   auth_tag_len = native_tag->size();
//   std::memcpy(auth_tag, native_tag->data(), auth_tag_len);
//   auth_tag_state = kAuthTagPassedToOpenSSL;

//   return true;
// }

}  // namespace margelo::nitro::crypto
