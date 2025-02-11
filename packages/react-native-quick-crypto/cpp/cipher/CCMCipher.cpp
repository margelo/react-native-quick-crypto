#include "CCMCipher.hpp"
#include <stdexcept>

// bool CCMCipher::setAuthTag(const uint8_t* tag, int tag_len) {
//   if (!tag || tag_len < 4 || tag_len > 16) {
//     return false;
//   }

//   if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tag_len, const_cast<uint8_t*>(tag))) {
//     return false;
//   }

//   auth_tag_state = kAuthTagPassedToOpenSSL;
//   return true;
// }

namespace margelo::nitro::crypto {

// CCMCipher::CCMCipher(const EVP_CIPHER* cipher,
//                      bool encrypt,
//                      const uint8_t* key,
//                      const uint8_t* iv,
//                      int iv_len)
//     : HybridCipher() {

//   // Initialize EVP context
//   ctx = EVP_CIPHER_CTX_new();
//   if (!ctx) {
//     throw std::runtime_error("Failed to create cipher context");
//   }

//   // Initialize with null key and IV first for CCM mode
//   if (EVP_CipherInit_ex2(ctx, cipher, nullptr, nullptr, encrypt ? 1 : 0, nullptr) != 1) {
//     EVP_CIPHER_CTX_free(ctx);
//     throw std::runtime_error("Failed to initialize cipher");
//   }

//   // Now set the key
//   if (EVP_CipherInit_ex2(ctx, nullptr, key, nullptr, -1, nullptr) != 1) {
//     EVP_CIPHER_CTX_free(ctx);
//     throw std::runtime_error("Failed to set key");
//   }

//   // Set IV length for CCM
//   if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, iv_len, nullptr) != 1) {
//     EVP_CIPHER_CTX_free(ctx);
//     throw std::runtime_error("Failed to set IV length");
//   }

//   // Set IV
//   if (EVP_CipherInit_ex2(ctx, nullptr, nullptr, iv, -1, nullptr) != 1) {
//     EVP_CIPHER_CTX_free(ctx);
//     throw std::runtime_error("Failed to set IV");
//   }

//   is_cipher = encrypt;
// }

// bool CCMCipher::initializeImpl() {
//   // CCM requires message length to be known in advance
//   has_aad = false;
//   auth_tag_len = 16;  // Default CCM tag length

//   // Set the tag length for CCM mode
//   if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, auth_tag_len, nullptr)) {
//     throw std::runtime_error("Failed to set CCM tag length");
//   }

//   return true;
// }

// bool CCMCipher::updateImpl(const uint8_t* data, int data_len, uint8_t* out, int* out_len) {
//   if (!has_aad) {
//     throw std::runtime_error("setAAD() must be called before update() in CCM mode");
//   }

//   // CCM mode requires one-shot encryption/decryption
//   return EVP_CipherUpdate(ctx, out, out_len, data, data_len) == 1;
// }

// bool CCMCipher::finalImpl(uint8_t* out, int* out_len) {
//   if (!EVP_CipherFinal_ex(ctx, out, out_len)) {
//     return false;
//   }

//   if (is_cipher) {
//     // For CCM mode, we need to get the tag after finalization
//     std::memset(auth_tag, 0, EVP_GCM_TLS_TAG_LEN);
//     if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, auth_tag_len, auth_tag)) {
//       throw std::runtime_error("CCM tag retrieval failed (length: " + std::to_string(auth_tag_len) + ")");
//     }
//     auth_tag_state = kAuthTagKnown;
//   }

//   return true;
// }

// bool CCMCipher::setAADImpl(const uint8_t* aad, int aad_len, int plaintext_len) {
//   if (!checkMessageLength(plaintext_len)) {
//     return false;
//   }

//   // For CCM mode, we must set the total plaintext length before processing AAD
//   if (!EVP_CipherUpdate(ctx, nullptr, nullptr, nullptr, plaintext_len)) {
//     return false;
//   }

//   // Process AAD if present
//   if (aad_len > 0 && aad != nullptr) {
//     int temp_len;
//     if (!EVP_CipherUpdate(ctx, nullptr, &temp_len, aad, aad_len)) {
//       return false;
//     }
//   }

//   has_aad = true;
//   return true;
// }

// bool CCMCipher::checkMessageLength(int message_len) {
//   if (message_len > kMaxMessageSize) {
//     throw std::runtime_error("Cannot create larger than " + std::to_string(kMaxMessageSize) + " bytes");
//   }
//   return true;
// }

}  // namespace margelo::nitro::crypto
