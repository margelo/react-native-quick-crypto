#include <stdexcept>
#include "CCMCipher.hpp"
#include "Utils.hpp"

namespace margelo::nitro::crypto {

void CCMCipher::init(
    const std::shared_ptr<ArrayBuffer> cipher_key,
    const std::shared_ptr<ArrayBuffer> iv
) {
  // For CCM mode, we need to:
  // 1. Initialize cipher with key and IV
  // 2. Set IV length
  // 3. Set tag length

  auto native_key = ToNativeArrayBuffer(cipher_key);
  auto native_iv = ToNativeArrayBuffer(iv);

  // Create cipher context if needed
  if (!ctx) {
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
      throw std::runtime_error("Failed to create cipher context");
    }
  }

  // Get cipher
  EVP_CIPHER* cipher = EVP_CIPHER_fetch(nullptr, cipher_type.c_str(), nullptr);
  if (!cipher) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("Invalid cipher type: " + cipher_type);
  }

  // Initialize cipher without key/IV
  if (!EVP_CipherInit_ex2(ctx, cipher, nullptr, nullptr, is_cipher ? 1 : 0, nullptr)) {
    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("Failed to initialize cipher");
  }

  // Set IV length
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, native_iv->size(), nullptr)) {
    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("Failed to set IV length");
  }

  // For CCM mode, we need to set the tag length during initialization
  if (is_cipher) {
    // When encrypting, set the tag length using EVP_CTRL_AEAD_SET_TAG
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, auth_tag_len, nullptr)) {
      EVP_CIPHER_free(cipher);
      EVP_CIPHER_CTX_free(ctx);
      throw std::runtime_error("Failed to set CCM tag length");
    }

    // Now set key and IV after setting tag length
    if (!EVP_CipherInit_ex2(ctx, nullptr, native_key->data(), native_iv->data(), -1, nullptr)) {
      EVP_CIPHER_free(cipher);
      EVP_CIPHER_CTX_free(ctx);
      throw std::runtime_error("Failed to set key and IV");
    }
  }

  EVP_CIPHER_free(cipher);
}

std::shared_ptr<ArrayBuffer> CCMCipher::update(const std::shared_ptr<ArrayBuffer>& data) {
  if (!ctx) {
    throw std::runtime_error("Cipher not initialized. Did you call setArgs()?");
  }

  if (!has_aad) {
    throw std::runtime_error("For CCM mode, setAAD() must be called before update()");
  }

  auto native_data = ToNativeArrayBuffer(data);
  size_t in_len = native_data->size();
  if (in_len > INT_MAX) {
    throw std::runtime_error("Message too long");
  }

  // Pass the authentication tag to OpenSSL if possible. This will only happen
  // once, usually on the first update.
  if (!is_cipher) {
    maybePassAuthTagToOpenSSL();
  }

  int buf_len = in_len + EVP_CIPHER_CTX_block_size(ctx);
  uint8_t* out = new uint8_t[buf_len];
  int out_len;

  if (EVP_CipherUpdate(ctx, out, &out_len, native_data->data(), in_len) != 1) {
    pending_auth_failed = true;
    throw std::runtime_error("Error in update(): " + std::string(ERR_reason_error_string(ERR_get_error())));
  }

  return std::make_shared<NativeArrayBuffer>(
    out,
    out_len,
    [=]() { delete[] out; }
  );
}

std::shared_ptr<ArrayBuffer> CCMCipher::final() {
  if (!ctx) {
    throw std::runtime_error("Cipher not initialized. Did you call setArgs()?");
  }

  int out_len = EVP_CIPHER_CTX_block_size(ctx);
  uint8_t* out = new uint8_t[out_len];

  // In CCM mode, final() only checks whether authentication failed in
  // update(). EVP_CipherFinal_ex must not be called and will fail.
  if (pending_auth_failed) {
    throw std::runtime_error("Authentication failed in update()");
    // out_len = 0;
    // out = new uint8_t[0];
  } else {
    // For CCM mode in encryption, get the tag after finalization
    if (is_cipher) {
      if (auth_tag_len == 0) {
        auth_tag_len = sizeof(auth_tag);
      }
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, auth_tag_len, auth_tag);
      auth_tag_state = kAuthTagKnown;
    }
  }

  return std::make_shared<NativeArrayBuffer>(
    out,
    out_len,
    [=]() { delete[] out; }
  );
}

bool CCMCipher::setAAD(const std::shared_ptr<ArrayBuffer>& data, std::optional<double> plaintextLength) {
  if (!ctx) {
    throw std::runtime_error("Cipher not initialized. Did you call setArgs()?");
  }

  if (!plaintextLength.has_value()) {
    throw std::runtime_error("CCM mode requires plaintextLength to be set");
  }

  // For CCM mode, we must set the total plaintext length before processing AAD
  int plaintext_len = static_cast<int>(plaintextLength.value());
  if (plaintext_len > kMaxMessageSize) {
    throw std::runtime_error("Message too long for CCM mode");
  }

  // For CCM mode in OpenSSL 3.3+, we need to set message length using OSSL_PARAM
  size_t msg_len = plaintext_len;
  OSSL_PARAM params[] = {
    OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, &msg_len),
    OSSL_PARAM_construct_end()
  };

  if (!EVP_CIPHER_CTX_set_params(ctx, params)) {
    throw std::runtime_error("Failed to set CCM message length");
  }

  // Process AAD if present
  auto native_data = ToNativeArrayBuffer(data);
  if (native_data->size() > 0) {
    int out_len = 0;
    // For CCM, we must pass nullptr as the output buffer when processing AAD
    if (!EVP_CipherUpdate(ctx, nullptr, &out_len, native_data->data(), native_data->size())) {
      throw std::runtime_error("Failed to process AAD");
    }
  }

  has_aad = true;
  return true;
}

bool CCMCipher::setAuthTag(const std::shared_ptr<ArrayBuffer>& tag) {
  if (!ctx) {
    throw std::runtime_error("Cipher not initialized. Did you call setArgs()?");
  }

  if (is_cipher) {
    throw std::runtime_error("Auth tag cannot be set when encrypting");
  }

  auto native_tag = ToNativeArrayBuffer(tag);
  if (native_tag->size() < 4 || native_tag->size() > 16) {
    throw std::runtime_error("Invalid auth tag length. Must be between 4 and 16 bytes.");
  }

  // For CCM mode, we need to set the tag using EVP_CTRL_AEAD_SET_TAG
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, native_tag->size(), const_cast<uint8_t*>(native_tag->data()))) {
    throw std::runtime_error("Failed to set auth tag");
  }

  auth_tag_len = native_tag->size();
  std::memcpy(auth_tag, native_tag->data(), auth_tag_len);
  auth_tag_state = kAuthTagPassedToOpenSSL;

  return true;
}

}  // namespace margelo::nitro::crypto
