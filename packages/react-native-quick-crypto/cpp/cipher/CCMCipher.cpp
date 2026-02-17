#include "CCMCipher.hpp"
#include "QuickCryptoUtils.hpp"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdexcept>

namespace margelo::nitro::crypto {

void CCMCipher::init(const std::shared_ptr<ArrayBuffer> cipher_key, const std::shared_ptr<ArrayBuffer> iv) {
  // 1. Call the base class initializer first
  try {
    HybridCipher::init(cipher_key, iv);
  } catch (const std::exception& e) {
    throw; // Re-throw after logging
  }

  // Ensure context is valid after base init
  checkCtx();

  // 2. Perform CCM-specific initialization
  auto native_iv = ToNativeArrayBuffer(iv);
  size_t iv_len = native_iv->size();

  // Set the IV length using CCM-specific control
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, iv_len, nullptr) != 1) {
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error("CCMCipher: Failed to set IV length: " + std::string(err_buf));
  }

  // Set the expected/output tag length using CCM-specific control.
  // auth_tag_len should have been defaulted or set via setArgs in the base init.
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, auth_tag_len, nullptr) != 1) {
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error("CCMCipher: Failed to set tag length: " + std::string(err_buf));
  }

  // Finally, initialize the key and IV using the parameters passed to this function.
  auto native_key = ToNativeArrayBuffer(cipher_key); // Use 'cipher_key' parameter
  const unsigned char* key_ptr = reinterpret_cast<const unsigned char*>(native_key->data());
  const unsigned char* iv_ptr = reinterpret_cast<const unsigned char*>(native_iv->data());

  // The last argument (is_cipher) should be consistent with the initial setup call.
  if (EVP_CipherInit_ex(ctx, nullptr, nullptr, key_ptr, iv_ptr, is_cipher) != 1) {
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error("CCMCipher: Failed to set key/IV: " + std::string(err_buf));
  }
}

std::shared_ptr<ArrayBuffer> CCMCipher::update(const std::shared_ptr<ArrayBuffer>& data) {
  checkCtx();
  checkNotFinalized();
  auto native_data = ToNativeArrayBuffer(data);
  size_t in_len = native_data->size();
  if (in_len < 0 || in_len > INT_MAX) {
    throw std::runtime_error("Invalid message length");
  }
  int out_len = 0;

  if (!is_cipher) {
    maybePassAuthTagToOpenSSL();
  }

  int block_size = EVP_CIPHER_CTX_block_size(ctx);
  if (block_size <= 0) {
    throw std::runtime_error("Invalid block size in update");
  }
  out_len = in_len + block_size - 1;
  if (out_len < 0 || out_len < in_len) {
    throw std::runtime_error("Calculated output buffer size invalid in update");
  }

  auto out_buf = std::make_unique<unsigned char[]>(out_len);
  const uint8_t* in = reinterpret_cast<const uint8_t*>(native_data->data());

  int actual_out_len = 0;
  int ret = EVP_CipherUpdate(ctx, out_buf.get(), &actual_out_len, in, in_len);

  if (!is_cipher) {
    // Decryption: Check for tag verification failure
    if (ret <= 0) {
      // Tag verification failed (or other decryption error)
      throw std::runtime_error("CCM Decryption: Tag verification failed");
    }
  } else {
    // Encryption: Check for standard errors
    if (ret != 1) {
      pending_auth_failed = true; // Should this be set for encryption failure?
      unsigned long err = ERR_get_error();
      char err_buf[256];
      ERR_error_string_n(err, err_buf, sizeof(err_buf));
      throw std::runtime_error("Error in update() performing encryption operation: " + std::string(err_buf));
    }
  }
  // If we reached here, the operation (encryption or decryption) succeeded

  unsigned char* final_output = out_buf.release();
  return std::make_shared<NativeArrayBuffer>(final_output, actual_out_len, [=]() { delete[] final_output; });
}

std::shared_ptr<ArrayBuffer> CCMCipher::final() {
  checkCtx();
  checkNotFinalized();

  // CCM decryption does not use final. Verification happens in the last update call.
  if (!is_cipher) {
    is_finalized = true;
    unsigned char* empty_output = new unsigned char[0];
    return std::make_shared<NativeArrayBuffer>(empty_output, 0, [=]() { delete[] empty_output; });
  }

  // Proceed only for encryption
  int block_size = EVP_CIPHER_CTX_block_size(ctx);
  if (block_size <= 0) {
    throw std::runtime_error("Invalid block size");
  }
  auto out_buf = std::make_unique<unsigned char[]>(block_size);
  int out_len = 0;

  if (!EVP_CipherFinal_ex(ctx, out_buf.get(), &out_len)) {
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error("Encryption finalization failed: " + std::string(err_buf));
  }

  if (auth_tag_len == 0) {
    auth_tag_len = sizeof(auth_tag);
  }

  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, auth_tag_len, auth_tag) != 1) {
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error("Failed to get auth tag after finalization: " + std::string(err_buf));
  }
  auth_tag_state = kAuthTagKnown;
  is_finalized = true;

  unsigned char* final_output = out_buf.release();
  return std::make_shared<NativeArrayBuffer>(final_output, out_len, [=]() { delete[] final_output; });
}

bool CCMCipher::setAAD(const std::shared_ptr<ArrayBuffer>& data, std::optional<double> plaintextLength) {
  checkCtx();
  if (!plaintextLength.has_value()) {
    throw std::runtime_error("CCM mode requires plaintextLength to be set");
  }

  // IMPORTANT: For CCM decryption (!is_cipher), OpenSSL requires this initial update
  // call to specify the TOTAL LENGTH OF THE CIPHERTEXT, not the plaintext.
  // The caller (JS) must ensure `plaintextLength` holds the ciphertext length when decrypting.
  int data_len = static_cast<int>(plaintextLength.value());
  if (data_len > kMaxMessageSize) {
    throw std::runtime_error("Provided data length exceeds maximum allowed size");
  }

  if (!is_cipher) {
    if (!maybePassAuthTagToOpenSSL()) {
      unsigned long err = ERR_get_error();
      char err_buf[256];
      ERR_error_string_n(err, err_buf, sizeof(err_buf));
      throw std::runtime_error("setAAD: Failed to set auth tag parameters: " + std::string(err_buf));
    }
  }

  int out_len = 0;

  // Get AAD data and length *before* deciding whether to set total length
  auto native_aad = ToNativeArrayBuffer(data);
  size_t aad_len = native_aad->size();

  // 1. Set the total *ciphertext* length. This seems necessary based on examples,
  //    BUT the wiki says "(only needed if AAD is passed)". Let's skip if decrypting and AAD length is 0.
  bool should_set_total_length = is_cipher || aad_len > 0;
  if (should_set_total_length) {
    if (EVP_CipherUpdate(ctx, nullptr, &out_len, nullptr, data_len) != 1) {
      unsigned long err = ERR_get_error();
      char err_buf[256];
      ERR_error_string_n(err, err_buf, sizeof(err_buf));
      throw std::runtime_error("CCMCipher: Failed to set expected length: " + std::string(err_buf));
    }
  }

  // 2. Process AAD Data
  // Per OpenSSL CCM decryption examples, this MUST be called even if aad_len is 0.
  // Pass nullptr as the output buffer, the AAD data pointer, and its length.
  if (EVP_CipherUpdate(ctx, nullptr, &out_len, native_aad->data(), aad_len) != 1) {
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error("CCMCipher: Failed to update AAD: " + std::string(err_buf));
  }
  return true;
}

} // namespace margelo::nitro::crypto
