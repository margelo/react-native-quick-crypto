#include "OCBCipher.hpp"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <cstring>

#include "Utils.hpp"
#include <cstdio>
#include <iomanip>

namespace margelo::nitro::crypto {

bool OCBCipher::setAAD(const std::shared_ptr<ArrayBuffer>& data, std::optional<double> plaintextLength) {
    auto native_aad = ToNativeArrayBuffer(data);
    size_t aad_len = native_aad->size();
    return HybridCipher::setAAD(data, plaintextLength);
}

std::shared_ptr<ArrayBuffer> OCBCipher::update(const std::shared_ptr<ArrayBuffer>& data) {
    auto native_data = ToNativeArrayBuffer(data);
    size_t data_len = native_data->size();
    return HybridCipher::update(data);
}

void OCBCipher::init(const std::shared_ptr<ArrayBuffer>& key,
                     const std::shared_ptr<ArrayBuffer>& iv,
                     size_t tag_len) {
    HybridCipher::init(key, iv);
    auth_tag_len = tag_len;

    // Set tag length for OCB (must be 12-16 bytes)
    if (auth_tag_len < 12 || auth_tag_len > 16) {
        throw std::runtime_error("OCB tag length must be between 12 and 16 bytes");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, auth_tag_len, nullptr) != 1) {
        throw std::runtime_error("Failed to set OCB tag length");
    }
}

std::shared_ptr<ArrayBuffer> OCBCipher::getAuthTag() {
    checkCtx();
    if (!is_cipher) {
        throw std::runtime_error("getAuthTag can only be called during encryption.");
    }
    auto tag_buf = std::make_unique<uint8_t[]>(auth_tag_len);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, auth_tag_len, tag_buf.get()) != 1) {
        throw std::runtime_error("Failed to get OCB auth tag");
    }
    uint8_t* raw_ptr = tag_buf.get();
    return std::make_shared<NativeArrayBuffer>(tag_buf.release(), auth_tag_len, [raw_ptr]() { delete[] raw_ptr; });
}

bool OCBCipher::setAuthTag(const std::shared_ptr<ArrayBuffer>& tag) {
    checkCtx();
    if (is_cipher) {
        throw std::runtime_error("setAuthTag can only be called during decryption.");
    }
    auto native_tag = ToNativeArrayBuffer(tag);
    size_t tag_len = native_tag->size();
    if (tag_len < 12 || tag_len > 16) {
        throw std::runtime_error("Invalid OCB tag length");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_len, native_tag->data()) != 1) {
        throw std::runtime_error("Failed to set OCB auth tag");
    }
    auth_tag_len = tag_len;
    return true;
}

} // namespace margelo::nitro::crypto
