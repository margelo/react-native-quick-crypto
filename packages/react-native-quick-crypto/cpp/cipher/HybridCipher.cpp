#include <algorithm> // For std::sort
#include <cstring>   // For std::memcpy
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "HybridCipher.hpp"
#include "QuickCryptoUtils.hpp"

#include <ncrypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>

namespace margelo::nitro::crypto {

HybridCipher::~HybridCipher() {
  if (ctx) {
    EVP_CIPHER_CTX_free(ctx);
    // No need to set ctx = nullptr here, object is being destroyed
  }
}

void HybridCipher::checkCtx() const {
  if (!ctx) {
    throw std::runtime_error("Cipher context is not initialized or has been disposed.");
  }
}

bool HybridCipher::maybePassAuthTagToOpenSSL() {
  if (auth_tag_state == kAuthTagKnown) {
    OSSL_PARAM params[] = {OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, auth_tag, auth_tag_len),
                           OSSL_PARAM_construct_end()};
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

void HybridCipher::init(const std::shared_ptr<ArrayBuffer> cipher_key, const std::shared_ptr<ArrayBuffer> iv) {
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

  // For base hybrid cipher, set key and IV immediately.
  // Derived classes like CCM might override init and handle this differently.
  auto native_key = ToNativeArrayBuffer(cipher_key);
  auto native_iv = ToNativeArrayBuffer(iv);
  const unsigned char* key_ptr = reinterpret_cast<const unsigned char*>(native_key->data());
  const unsigned char* iv_ptr = reinterpret_cast<const unsigned char*>(native_iv->data());

  if (EVP_CipherInit_ex(ctx, nullptr, nullptr, key_ptr, iv_ptr, is_cipher) != 1) {
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    EVP_CIPHER_CTX_free(ctx);
    ctx = nullptr;
    throw std::runtime_error("HybridCipher: Failed to set key/IV: " + std::string(err_buf));
  }

  // For AES-KW (wrap ciphers), set the WRAP_ALLOW flag and disable padding
  std::string cipher_name(cipher_type);
  if (cipher_name.find("-wrap") != std::string::npos) {
    // This flag is required for AES-KW in OpenSSL 3.x
    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
  }
}

std::shared_ptr<ArrayBuffer> HybridCipher::update(const std::shared_ptr<ArrayBuffer>& data) {
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
  int ret = EVP_CipherUpdate(ctx, out, &out_len, native_data->data(), in_len);

  if (!ret) {
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    delete[] out;
    throw std::runtime_error("Cipher update failed: " + std::string(err_buf));
  }

  // Create and return a new buffer of exact size needed
  return std::make_shared<NativeArrayBuffer>(out, out_len, [=]() { delete[] out; });
}

std::shared_ptr<ArrayBuffer> HybridCipher::final() {
  checkCtx();
  // Block size is max output size for final, unless EVP_CIPH_NO_PADDING is set
  int block_size = EVP_CIPHER_CTX_block_size(ctx);
  if (block_size <= 0)
    block_size = 16; // Default if block size is weird (e.g., 0)
  auto out_buf = std::make_unique<uint8_t[]>(block_size);
  int out_len = 0;

  int ret = EVP_CipherFinal_ex(ctx, out_buf.get(), &out_len);
  if (!ret) {
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    // Don't free context on error here either, rely on destructor
    throw std::runtime_error("Cipher final failed: " + std::string(err_buf));
  }

  // Get raw pointer before releasing unique_ptr
  uint8_t* raw_ptr = out_buf.get();
  // Create the specific NativeArrayBuffer first, using full namespace
  auto native_final_chunk = std::make_shared<margelo::nitro::NativeArrayBuffer>(out_buf.release(), static_cast<size_t>(out_len),
                                                                                [raw_ptr]() { delete[] raw_ptr; });

  // Context should NOT be freed here. It might be needed for getAuthTag() for GCM/OCB.
  // The context will be freed by the destructor (~HybridCipher) when the object goes out of scope.

  // Return the shared_ptr<NativeArrayBuffer> (implicit upcast to shared_ptr<ArrayBuffer>)
  return native_final_chunk;
}

bool HybridCipher::setAAD(const std::shared_ptr<ArrayBuffer>& data, std::optional<double> plaintextLength) {
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

bool HybridCipher::setAutoPadding(bool autoPad) {
  checkCtx();
  return EVP_CIPHER_CTX_set_padding(ctx, autoPad) == 1;
}

bool HybridCipher::setAuthTag(const std::shared_ptr<ArrayBuffer>& tag) {
  checkCtx();

  if (is_cipher) {
    throw std::runtime_error("setAuthTag can only be called during decryption.");
  }

  auto native_tag = ToNativeArrayBuffer(tag);
  size_t tag_len = native_tag->size();
  uint8_t* tag_ptr = native_tag->data();

  int mode = EVP_CIPHER_CTX_mode(ctx);

  if (mode == EVP_CIPH_GCM_MODE || mode == EVP_CIPH_OCB_MODE) {
    // Use EVP_CTRL_AEAD_SET_TAG for GCM/OCB decryption
    if (tag_len < 1 || tag_len > 16) { // Check tag length bounds for GCM/OCB
      throw std::runtime_error("Invalid auth tag length for GCM/OCB. Must be between 1 and 16 bytes.");
    }
    // Add check for valid cipher in context before setting tag
    // Use the correct OpenSSL 3 function: EVP_CIPHER_CTX_cipher
    if (!EVP_CIPHER_CTX_cipher(ctx)) {
      throw std::runtime_error("Context has no cipher set before setting GCM/OCB tag");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_len, tag_ptr) <= 0) {
      unsigned long err = ERR_get_error();
      char err_buf[256];
      ERR_error_string_n(err, err_buf, sizeof(err_buf));
      // Include the error code in the message
      throw std::runtime_error("Failed to set GCM/OCB auth tag: " + std::string(err_buf) + " (code: " + std::to_string(err) + ")");
    }
    auth_tag_state = kAuthTagPassedToOpenSSL; // Mark state
    return true;

  } else if (mode == EVP_CIPH_CCM_MODE) {
    // Store tag internally for CCM decryption (used in CCMCipher::final)
    if (tag_len < 4 || tag_len > 16) { // Check tag length bounds for CCM
      throw std::runtime_error("Invalid auth tag length for CCM. Must be between 4 and 16 bytes.");
    }
    auth_tag_state = kAuthTagKnown; // Correct state enum value
    auth_tag_len = tag_len;
    // Copy directly into the member buffer (assuming uint8_t auth_tag[16])
    std::memcpy(auth_tag, tag_ptr, tag_len);
    return true;

  } else {
    // Not an AEAD mode that supports setAuthTag for decryption
    throw std::runtime_error("setAuthTag is not supported for the current cipher mode.");
  }
}

std::shared_ptr<ArrayBuffer> HybridCipher::getAuthTag() {
  checkCtx();

  int mode = EVP_CIPHER_CTX_mode(ctx);

  if (!is_cipher) {
    throw std::runtime_error("getAuthTag can only be called during encryption.");
  }

  if (mode == EVP_CIPH_GCM_MODE || mode == EVP_CIPH_OCB_MODE) {
    // Retrieve the tag using EVP_CIPHER_CTX_ctrl for GCM/OCB
    constexpr int max_tag_len = 16; // GCM/OCB tags are typically up to 16 bytes
    auto tag_buf = std::make_unique<uint8_t[]>(max_tag_len);

    int ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, max_tag_len, tag_buf.get());

    if (ret <= 0) {
      unsigned long err = ERR_get_error();
      char err_buf[256];
      ERR_error_string_n(err, err_buf, sizeof(err_buf));
      throw std::runtime_error("Failed to get GCM/OCB auth tag: " + std::string(err_buf));
    }

    uint8_t* raw_ptr = tag_buf.get();
    auto final_tag_buffer =
        std::make_shared<margelo::nitro::NativeArrayBuffer>(tag_buf.release(), auth_tag_len, [raw_ptr]() { delete[] raw_ptr; });
    return final_tag_buffer;

  } else if (mode == EVP_CIPH_CCM_MODE) {
    // CCM: allow getAuthTag after encryption/finalization
    if (auth_tag_len > 0 && auth_tag_state == kAuthTagKnown) {
      // Return the stored tag buffer
      auto tag_buf = std::make_unique<uint8_t[]>(auth_tag_len);
      std::memcpy(tag_buf.get(), auth_tag, auth_tag_len);
      uint8_t* raw_ptr = tag_buf.get();
      auto final_tag_buffer =
          std::make_shared<margelo::nitro::NativeArrayBuffer>(tag_buf.release(), auth_tag_len, [raw_ptr]() { delete[] raw_ptr; });
      return final_tag_buffer;
    } else {
      throw std::runtime_error("CCM: Auth tag not available. Ensure encryption is finalized before calling getAuthTag.");
    }
  } else {
    // Not an AEAD mode that supports getAuthTag post-encryption
    throw std::runtime_error("getAuthTag is not supported for the current cipher mode.");
  }
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

// Corrected callback signature for EVP_CIPHER_do_all_provided
void collect_ciphers(EVP_CIPHER* cipher, void* arg) {
  auto* names = static_cast<std::vector<std::string>*>(arg);
  if (cipher == nullptr)
    return;
  // Note: EVP_CIPHER_get0_name expects const EVP_CIPHER*, but the callback provides EVP_CIPHER*.
  // This implicit const cast should be safe here.
  const char* name = EVP_CIPHER_get0_name(cipher);
  if (name != nullptr) {
    std::string name_str(name);
    if (name_str == "NULL" || name_str.find("CTS") != std::string::npos ||
        name_str.find("SIV") != std::string::npos ||  // Covers -SIV and -GCM-SIV
        name_str.find("WRAP") != std::string::npos || // Covers -WRAP-INV and -WRAP-PAD-INV
        name_str.find("SM4-") != std::string::npos ||
        name_str.find("-ETM") != std::string::npos) { // TLS-internal ciphers, not for general use
      return;                                         // Skip adding this cipher
    }

    // If not filtered out, add it to the list
    names->push_back(name_str); // Use name_str here
  }
}

std::vector<std::string> HybridCipher::getSupportedCiphers() {
  std::vector<std::string> cipher_names;

  // Use the simpler approach with the separate callback
  EVP_CIPHER_do_all_provided(nullptr, // Default library context
                             collect_ciphers, &cipher_names);

  // OpenSSL 3 doesn't guarantee sorted output with _do_all_provided, sort manually
  std::sort(cipher_names.begin(), cipher_names.end());

  return cipher_names;
}

std::optional<CipherInfo> HybridCipher::getCipherInfo(const std::string& name, std::optional<double> keyLength,
                                                      std::optional<double> ivLength) {
  auto cipher = ncrypto::Cipher::FromName(name.c_str());
  if (!cipher)
    return std::nullopt;

  size_t iv_length = cipher.getIvLength();
  size_t key_length = cipher.getKeyLength();

  if (keyLength.has_value() || ivLength.has_value()) {
    auto ctx = ncrypto::CipherCtxPointer::New();
    if (!ctx.init(cipher, true))
      return std::nullopt;

    if (keyLength.has_value()) {
      size_t check_len = static_cast<size_t>(keyLength.value());
      if (!ctx.setKeyLength(check_len))
        return std::nullopt;
      key_length = check_len;
    }

    if (ivLength.has_value()) {
      size_t check_len = static_cast<size_t>(ivLength.value());
      if (cipher.isCcmMode()) {
        if (check_len < 7 || check_len > 13)
          return std::nullopt;
      } else if (cipher.isGcmMode()) {
        // GCM accepts flexible IV lengths
      } else if (cipher.isOcbMode()) {
        if (!ctx.setIvLength(check_len))
          return std::nullopt;
      } else {
        if (check_len != iv_length)
          return std::nullopt;
      }
      iv_length = check_len;
    }
  }

  std::string name_str(name);
  std::transform(name_str.begin(), name_str.end(), name_str.begin(), ::tolower);

  std::string mode_str(cipher.getModeLabel());

  std::optional<double> block_size = std::nullopt;
  if (!cipher.isStreamMode()) {
    block_size = static_cast<double>(cipher.getBlockSize());
  }

  std::optional<double> iv_len = std::nullopt;
  if (iv_length != 0) {
    iv_len = static_cast<double>(iv_length);
  }

  return CipherInfo{name_str, static_cast<double>(cipher.getNid()), mode_str, static_cast<double>(key_length), block_size, iv_len};
}

} // namespace margelo::nitro::crypto
