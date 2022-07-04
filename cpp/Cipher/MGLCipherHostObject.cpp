//
// Created by Oscar on 07.06.22.
//
#include "MGLCipherHostObject.h"

#ifdef ANDROID
#include "JSIUtils/MGLJSIUtils.h"
#include "JSIUtils/MGLTypedArray.h"
#else
#include "MGLJSIUtils.h"
#include "MGLTypedArray.h"
#endif

#include <openssl/evp.h>

#include <algorithm>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#define OUT

// TODO(osp) Some of the code is inspired or copied from node-js, check if
// attribution is needed
namespace margelo {

namespace jsi = facebook::jsi;

// TODO(osp) move this to constants file (crypto_aes.cpp in node)
constexpr unsigned kNoAuthTagLength = static_cast<unsigned>(-1);

bool IsSupportedAuthenticatedMode(const EVP_CIPHER *cipher) {
  switch (EVP_CIPHER_mode(cipher)) {
    case EVP_CIPH_CCM_MODE:
    case EVP_CIPH_GCM_MODE:
#ifndef OPENSSL_NO_OCB
    case EVP_CIPH_OCB_MODE:
#endif
      return true;
    case EVP_CIPH_STREAM_CIPHER:
      return EVP_CIPHER_nid(cipher) == NID_chacha20_poly1305;
    default:
      return false;
  }
}

bool IsSupportedAuthenticatedMode(const EVP_CIPHER_CTX *ctx) {
  const EVP_CIPHER *cipher = EVP_CIPHER_CTX_cipher(ctx);
  return IsSupportedAuthenticatedMode(cipher);
}

bool IsValidGCMTagLength(unsigned int tag_len) {
  return tag_len == 4 || tag_len == 8 || (tag_len >= 12 && tag_len <= 16);
}

void CopyTo(jsi::Runtime &runtime, jsi::ArrayBuffer *src, char *dest,
            size_t len) {
  //  static_assert(sizeof(M) == 1, "sizeof(M) must equal 1");
  len = std::min(len, src->size(runtime));
  if (len > 0 && src->data(runtime) != nullptr)
    memcpy(dest, src->data(runtime), len);
}

MGLCipherHostObject::MGLCipherHostObject(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue)
    : MGLSmartHostObject(jsCallInvoker, workerQueue) {
  installMethods();
}

MGLCipherHostObject::MGLCipherHostObject(
    MGLCipherHostObject *other,
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue)
    : MGLSmartHostObject(jsCallInvoker, workerQueue),
      isCipher_(other->isCipher_) {
  installMethods();
}

MGLCipherHostObject::MGLCipherHostObject(
    const std::string &cipher_type, jsi::ArrayBuffer *cipher_key, bool isCipher,
    unsigned int auth_tag_len, jsi::Runtime &runtime,
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue)
    : MGLSmartHostObject(jsCallInvoker, workerQueue),
      isCipher_(isCipher),
      pending_auth_failed_(false) {
  // TODO(osp) is this needed on the SSL version we are using?
  // #if OPENSSL_VERSION_MAJOR >= 3
  //    if (EVP_default_properties_is_fips_enabled(nullptr)) {
  // #else
  //    if (FIPS_mode()) {
  // #endif
  //        return THROW_ERR_CRYPTO_UNSUPPORTED_OPERATION(env(),
  //                                                      "crypto.createCipher()
  //                                                      is not supported in
  //                                                      FIPS mode.");
  //    }

  const EVP_CIPHER *const cipher = EVP_get_cipherbyname(cipher_type.c_str());
  if (cipher == nullptr) {
    throw jsi::JSError(runtime, "Invalid Cipher Algorithm!");
  }

  unsigned char key[EVP_MAX_KEY_LENGTH];
  unsigned char iv[EVP_MAX_IV_LENGTH];

  int key_len =
      EVP_BytesToKey(cipher, EVP_md5(), nullptr, cipher_key->data(runtime),
                     static_cast<int>(cipher_key->size(runtime)), 1, key, iv);

  // TODO(osp) this looks like a macro, check if necessary
  // CHECK_NE(key_len, 0);

  // TODO(osp) this seems like a runtime check
  //  const int mode = EVP_CIPHER_mode(cipher);
  //  if (isCipher && (mode == EVP_CIPH_CTR_MODE ||
  //                           mode == EVP_CIPH_GCM_MODE ||
  //                           mode == EVP_CIPH_CCM_MODE)) {
  //    // Ignore the return value (i.e. possible exception) because we are
  //    // not calling back into JS anyway.
  //    ProcessEmitWarning(env(),
  //                       "Use Cipheriv for counter mode of %s",
  //                       cipher_type);
  //  }

  commonInit(runtime, cipher_type.c_str(), cipher, key, key_len, iv,
             EVP_CIPHER_iv_length(cipher), auth_tag_len);

  installMethods();
}

MGLCipherHostObject::MGLCipherHostObject(
    const std::string &cipher_type, jsi::ArrayBuffer *cipher_key, bool isCipher,
    unsigned int auth_tag_len, jsi::ArrayBuffer *iv, jsi::Runtime &runtime,
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue)
    : MGLSmartHostObject(jsCallInvoker, workerQueue),
      isCipher_(isCipher),
      pending_auth_failed_(false) {
  // TODO(osp) is this needed on the SSL version we are using?
  // #if OPENSSL_VERSION_MAJOR >= 3
  //    if (EVP_default_properties_is_fips_enabled(nullptr)) {
  // #else
  //    if (FIPS_mode()) {
  // #endif
  //        return THROW_ERR_CRYPTO_UNSUPPORTED_OPERATION(env(),
  //                                                      "crypto.createCipher()
  //                                                      is not supported in
  //                                                      FIPS mode.");
  //    }

  const EVP_CIPHER *const cipher = EVP_get_cipherbyname(cipher_type.c_str());
  if (cipher == nullptr) {
    throw jsi::JSError(runtime, "Invalid Cipher Algorithm!");
  }

  const int expected_iv_len = EVP_CIPHER_iv_length(cipher);
  const int is_authenticated_mode = IsSupportedAuthenticatedMode(cipher);
  const bool has_iv = iv->size(runtime) > 0;

  // Throw if an IV was passed which does not match the cipher's fixed IV length
  // static_cast<int> for the iv_buf.size() is safe because we've verified
  // prior that the value is not larger than MAX_INT.
  if (!is_authenticated_mode && has_iv &&
      static_cast<int>(iv->size(runtime)) != expected_iv_len) {
    throw jsi::JSError(runtime, "Invalid iv");
  }

  if (EVP_CIPHER_nid(cipher) == NID_chacha20_poly1305) {
    //        CHECK(has_iv);
    // Check for invalid IV lengths, since OpenSSL does not under some
    // conditions:
    //   https://www.openssl.org/news/secadv/20190306.txt.
    if (iv->size(runtime) > 12) throw jsi::JSError(runtime, "Invalid iv");
  }

  commonInit(runtime, cipher_type.c_str(), cipher, cipher_key->data(runtime),
             cipher_key->size(runtime), iv->data(runtime), iv->size(runtime),
             auth_tag_len);

  installMethods();
}

void MGLCipherHostObject::commonInit(jsi::Runtime &runtime,
                                     const char *cipher_type,
                                     const EVP_CIPHER *cipher,
                                     const unsigned char *key, int key_len,
                                     const unsigned char *iv, int iv_len,
                                     unsigned int auth_tag_len) {
  // TODO(osp) check for this macro
  //  CHECK(!ctx_);

  EVP_CIPHER_CTX_free(ctx_);
  ctx_ = EVP_CIPHER_CTX_new();

  const int mode = EVP_CIPHER_mode(cipher);
  if (mode == EVP_CIPH_WRAP_MODE) {
    EVP_CIPHER_CTX_set_flags(ctx_, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
  }

  if (1 !=
      EVP_CipherInit_ex(ctx_, cipher, nullptr, nullptr, nullptr, isCipher_)) {
    throw jsi::JSError(runtime, "Failed to initialize cipher");
  }

  if (IsSupportedAuthenticatedMode(cipher)) {
    // TODO(osp) implement this check macro
    //    CHECK_GE(iv_len, 0);
    if (!InitAuthenticated(cipher_type, iv_len, auth_tag_len)) {
      return;
    }
  }

  if (!EVP_CIPHER_CTX_set_key_length(ctx_, key_len)) {
    EVP_CIPHER_CTX_free(ctx_);
    ctx_ = nullptr;
    throw std::runtime_error("Invalid Cipher key length!");
  }

  if (1 != EVP_CipherInit_ex(ctx_, nullptr, nullptr, key, iv, isCipher_)) {
    throw std::runtime_error("Failed to initialize cipher!");
  }
}

void MGLCipherHostObject::installMethods() {
  // Instance methods

  // update
  this->fields.push_back(buildPair(
      "update", JSIF([this]) {
        if (count != 1) {
          throw jsi::JSError(runtime,
                             "cipher.update requires at least 2 parameters");
        }

        if (!arguments[0].isObject() ||
            !arguments[0].asObject(runtime).isArrayBuffer(runtime)) {
          throw jsi::JSError(runtime,
                             "cipher.update first argument ('data') needs to "
                             "be an ArrayBuffer");
        }

        auto dataArrayBuffer =
            arguments[0].asObject(runtime).getArrayBuffer(runtime);

        const unsigned char *data = dataArrayBuffer.data(runtime);
        auto len = dataArrayBuffer.length(runtime);

        if (ctx_ == nullptr || len > INT_MAX) {
          // On the node version there are several layers of wrapping and errors
          // are not immediately surfaced On our version we can simply throw an
          // error as soon as something goes wrong
          throw jsi::JSError(runtime, "kErrorState");
        }

        const int mode = EVP_CIPHER_CTX_mode(ctx_);

        if (mode == EVP_CIPH_CCM_MODE && !CheckCCMMessageLength(len)) {
          throw jsi::JSError(runtime, "kErrorMessageSize");
        }

        // Pass the authentication tag to OpenSSL if possible. This will only
        // happen once, usually on the first update.
        if (!isCipher_ && IsAuthenticatedMode()) {
          // TODO(osp) check
          MaybePassAuthTagToOpenSSL();
        }

        int buf_len = len + EVP_CIPHER_CTX_block_size(ctx_);
        // For key wrapping algorithms, get output size by calling
        // EVP_CipherUpdate() with null output.
        if (isCipher_ && mode == EVP_CIPH_WRAP_MODE &&
            EVP_CipherUpdate(ctx_, nullptr, &buf_len, data, len) != 1) {
          throw jsi::JSError(runtime, "kErrorState");
        }

        MGLTypedArray<MGLTypedArrayKind::Uint8Array> out(runtime, buf_len);

        // Important this function returns the real size of the data in buf_len
        // Output needs to be truncated to not send extra 0s
        int r = EVP_CipherUpdate(ctx_, out.getBuffer(runtime).data(runtime),
                                 &buf_len, data, len);

        // Trim exceeding bytes
        MGLTypedArray<MGLTypedArrayKind::Uint8Array> ret(runtime, buf_len);
        std::vector<unsigned char> vec(
            out.getBuffer(runtime).data(runtime),
            out.getBuffer(runtime).data(runtime) + buf_len);
        ret.update(runtime, vec);

        // When in CCM mode, EVP_CipherUpdate will fail if the authentication
        // tag is invalid. In that case, remember the error and throw in
        // final().
        if (!r && !isCipher_ && mode == EVP_CIPH_CCM_MODE) {
          pending_auth_failed_ = true;
          return ret;
        }

        //    return r == 1 ? jsi::Value((int)kSuccess) :
        //    jsi::Value((int)kErrorState);
        return ret;
      }));

  // final
  this->fields.push_back(HOST_LAMBDA("final", {
    if (ctx_ == nullptr) {
      throw jsi::JSError(runtime, "kErrorState");
    }

    const int mode = EVP_CIPHER_CTX_mode(ctx_);

    int buf_len = EVP_CIPHER_CTX_block_size(ctx_);
    MGLTypedArray<MGLTypedArrayKind::Uint8Array> out(runtime, buf_len);

    if (!isCipher_ && IsSupportedAuthenticatedMode(ctx_)) {
      MaybePassAuthTagToOpenSSL();
    }

    // In CCM mode, final() only checks whether authentication failed in
    // update(). EVP_CipherFinal_ex must not be called and will fail.
    bool ok;
    int out_len = out.byteLength(runtime);
    if (!isCipher_ && mode == EVP_CIPH_CCM_MODE) {
      ok = !pending_auth_failed_;
      MGLTypedArray<MGLTypedArrayKind::Uint8Array> out(runtime, 0);
    } else {
      ok = EVP_CipherFinal_ex(ctx_, out.getBuffer(runtime).data(runtime),
                              &out_len) == 1;

      if (ok && isCipher_ && IsAuthenticatedMode()) {
        // In GCM mode, the authentication tag length can be specified in
        // advance, but defaults to 16 bytes when encrypting. In CCM and OCB
        // mode, it must always be given by the user.
        if (auth_tag_len_ == kNoAuthTagLength) {
          // TODO(osp) check
          // CHECK(mode == EVP_CIPH_GCM_MODE);
          auth_tag_len_ = sizeof(auth_tag_);
        }
        ok = (1 == EVP_CIPHER_CTX_ctrl(
                       ctx_, EVP_CTRL_AEAD_GET_TAG, auth_tag_len_,
                       reinterpret_cast<unsigned char *>(auth_tag_)));
      }
    }

    MGLTypedArray<MGLTypedArrayKind::Uint8Array> ret(runtime, out_len);
    if (out_len > 0) {
      std::vector<unsigned char> vec(
          out.getBuffer(runtime).data(runtime),
          out.getBuffer(runtime).data(runtime) + out_len);
      ret.update(runtime, vec);
    }

    EVP_CIPHER_CTX_free(ctx_);
    ctx_ = nullptr;

    return ret;
  }));

  // setAAD
  this->fields.push_back(HOST_LAMBDA("setAAD", {
    if (count != 1) {
      throw jsi::JSError(runtime, "cipher.setAAD requires an argument record");
    }

    if (!arguments[0].isObject()) {
      throw jsi::JSError(runtime,
                         "cipher.setAAD first argument needs to be a record");
    }

    auto args = arguments[0].asObject(runtime);

    if (!args.hasProperty(runtime, "data") ||
        !args.getProperty(runtime, "data").isObject() ||
        !args.getProperty(runtime, "data")
             .asObject(runtime)
             .isArrayBuffer(runtime)) {
      throw jsi::JSError(runtime, "data is missing in arguments record");
    }

    auto dataArrayBuffer = args.getProperty(runtime, "data")
                               .asObject(runtime)
                               .getArrayBuffer(runtime);

    int plaintext_len = -1;
    if (args.hasProperty(runtime, "plaintextLength") &&
        !args.getProperty(runtime, "plaintextLength").isNull() &&
        !args.getProperty(runtime, "plaintextLength").isUndefined()) {
      if (args.getProperty(runtime, "plaintextLength").isNumber()) {
        plaintext_len =
            (int)args.getProperty(runtime, "plaintextLength").asNumber();
      } else {
        throw new jsi::JSError(runtime,
                               "plaintextLength property needs to be a number");
      }
    }

    const unsigned char *data = dataArrayBuffer.data(runtime);
    auto len = dataArrayBuffer.length(runtime);

    if (!ctx_ || !IsAuthenticatedMode()) return false;

    int outlen;
    const int mode = EVP_CIPHER_CTX_mode(ctx_);

    // When in CCM mode, we need to set the authentication tag and the plaintext
    // length in advance.
    if (mode == EVP_CIPH_CCM_MODE) {
      if (plaintext_len < 0) {
        throw jsi::JSError(runtime,
                           "plaintextLength required for CCM mode with AAD");
        return false;
      }

      if (!CheckCCMMessageLength(plaintext_len)) return false;

      if (!isCipher_) {
        if (!MaybePassAuthTagToOpenSSL()) return false;
      }

      // Specify the plaintext length.
      if (!EVP_CipherUpdate(ctx_, nullptr, &outlen, nullptr, plaintext_len))
        return false;
    }

    return 1 == EVP_CipherUpdate(ctx_, nullptr, &outlen, data, len);
  }));

  //  setAutoPadding
  this->fields.push_back(HOST_LAMBDA("setAutoPadding", {
    if (count != 1) {
      throw jsi::JSError(
          runtime, "cipher.setAutoPadding requires at least one argument");
    }

    if (!arguments[0].isBool()) {
      throw jsi::JSError(
          runtime, "cipher.setAutoPadding first argument must be a boolean");
    }

    if (ctx_ == nullptr) {
      return false;
    }

    return EVP_CIPHER_CTX_set_padding(ctx_, arguments[0].getBool());
  }));

  // setAuthTag
  this->fields.push_back(buildPair(
      "setAuthTag", JSIF([=]) {
        if (count != 1 || !arguments[0].isObject() ||
            !arguments[0].asObject(runtime).isArrayBuffer(runtime)) {
          jsi::detail::throwJSError(
              runtime,
              "cipher.setAuthTag requires an ArrayBuffer tag argument");
          throw jsi::JSError(
              runtime,
              "cipher.setAuthTag requires an ArrayBuffer tag argument");
        }

        if (!ctx_ || !IsAuthenticatedMode() || isCipher_ ||
            auth_tag_state_ != kAuthTagUnknown) {
          return false;
        }

        auto authTagArrayBuffer =
            arguments[0].asObject(runtime).getArrayBuffer(runtime);
        if (!CheckSizeInt32(runtime, authTagArrayBuffer)) {
          jsi::detail::throwJSError(
              runtime,
              "cipher.setAuthTag requires an ArrayBuffer tag argument");
          throw jsi::JSError(
              runtime,
              "cipher.setAuthTag requires an ArrayBuffer tag argument");
        }
        //    const unsigned char *data = authTagArrayBuffer.data(runtime);
        unsigned int tag_len =
            static_cast<unsigned int>(authTagArrayBuffer.length(runtime));

        //    ArrayBufferOrViewContents<char> auth_tag(args[0]);
        // TODO(osp) implement this check
        //    if (UNLIKELY(!auth_tag.CheckSizeInt32()))
        //      return THROW_ERR_OUT_OF_RANGE(env, "buffer is too big");

        //        unsigned int tag_len = auth_tag.size();

        const int mode = EVP_CIPHER_CTX_mode(ctx_);
        bool is_valid;
        if (mode == EVP_CIPH_GCM_MODE) {
          // Restrict GCM tag lengths according to NIST 800-38d, page 9.
          is_valid =
              (auth_tag_len_ == kNoAuthTagLength || auth_tag_len_ == tag_len) &&
              IsValidGCMTagLength(tag_len);
        } else {
          // At this point, the tag length is already known and must match the
          // length of the given authentication tag.
          // TODO(osp) add CHECK here
          IsSupportedAuthenticatedMode(ctx_);
          //      CHECK_NE(cipher->auth_tag_len_, kNoAuthTagLength);
          is_valid = auth_tag_len_ == tag_len;
        }

        if (!is_valid) {
          jsi::detail::throwJSError(runtime,
                                    "Invalid authentication tag length");
          throw jsi::JSError(runtime, "Invalid authentication tag length");
        }

        auth_tag_len_ = tag_len;
        auth_tag_state_ = kAuthTagKnown;
        //    CHECK_LE(cipher->auth_tag_len_, sizeof(cipher->auth_tag_));

        memset(auth_tag_, 0, sizeof(auth_tag_));
        CopyTo(runtime, &authTagArrayBuffer, auth_tag_, auth_tag_len_);

        return true;
      }));
}

bool MGLCipherHostObject::MaybePassAuthTagToOpenSSL() {
  if (auth_tag_state_ == kAuthTagKnown) {
    if (!EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_AEAD_SET_TAG, auth_tag_len_,
                             reinterpret_cast<unsigned char *>(auth_tag_))) {
      return false;
    }
    auth_tag_state_ = kAuthTagPassedToOpenSSL;
  }
  return true;
}

bool MGLCipherHostObject::IsAuthenticatedMode() const {
  // Check if this cipher operates in an AEAD mode that we support.
  //  CHECK(ctx_);
  return IsSupportedAuthenticatedMode(ctx_);
}

bool MGLCipherHostObject::InitAuthenticated(const char *cipher_type, int iv_len,
                                            unsigned int auth_tag_len) {
  // TODO(osp) implement this check
  //      CHECK(IsAuthenticatedMode());
  // TODO(osp) what is this? some sort of node error?
  //      MarkPopErrorOnReturn mark_pop_error_on_return;

  if (!EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_AEAD_SET_IVLEN, iv_len, nullptr)) {
    //    throw std::runtime_error("Invalid Cipher IV");
    //        THROW_ERR_CRYPTO_INVALID_IV(env());
    return false;
  }

  const int mode = EVP_CIPHER_CTX_mode(ctx_);
  if (mode == EVP_CIPH_GCM_MODE) {
    if (auth_tag_len != kNoAuthTagLength) {
      if (!IsValidGCMTagLength(auth_tag_len)) {
        //        throw std::runtime_error("Invalid Cipher authentication tag
        //        length!");
        //            THROW_ERR_CRYPTO_INVALID_AUTH_TAG(
        //                    env(),
        //                    "Invalid authentication tag length: %u",
        //                    auth_tag_len);
        return false;
      }

      // Remember the given authentication tag length for later.
      auth_tag_len_ = auth_tag_len;
    }
  } else {
    if (auth_tag_len == kNoAuthTagLength) {
      // We treat ChaCha20-Poly1305 specially. Like GCM, the authentication tag
      // length defaults to 16 bytes when encrypting. Unlike GCM, the
      // authentication tag length also defaults to 16 bytes when decrypting,
      // whereas GCM would accept any valid authentication tag length.
      if (EVP_CIPHER_CTX_nid(ctx_) == NID_chacha20_poly1305) {
        auth_tag_len = 16;
      } else {
        //        throw std::runtime_error("authTagLength required for cipher
        //        type");
        //            THROW_ERR_CRYPTO_INVALID_AUTH_TAG(
        //                    env(), "authTagLength required for %s",
        //                    cipher_type);
        return false;
      }
    }

    // TODO(tniessen) Support CCM decryption in FIPS mode

#if OPENSSL_VERSION_MAJOR >= 3
    if (mode == EVP_CIPH_CCM_MODE && kind_ == kDecipher &&
        EVP_default_properties_is_fips_enabled(nullptr)) {
#else
    if (mode == EVP_CIPH_CCM_MODE && !isCipher_ && FIPS_mode()) {
#endif
      //      throw std::runtime_error("CCM encryption not supported in FIPS
      //      mode");
      //          THROW_ERR_CRYPTO_UNSUPPORTED_OPERATION(env(),
      //                                                 "CCM encryption not
      //                                                 supported in FIPS
      //                                                 mode");
      return false;
    }

    // Tell OpenSSL about the desired length.
    if (!EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_AEAD_SET_TAG, auth_tag_len,
                             nullptr)) {
      //      throw std::runtime_error("Invalid authentication tag length");
      //          THROW_ERR_CRYPTO_INVALID_AUTH_TAG(
      //                  env(), "Invalid authentication tag length: %u",
      //                  auth_tag_len);
      return false;
    }

    // Remember the given authentication tag length for later.
    auth_tag_len_ = auth_tag_len;

    if (mode == EVP_CIPH_CCM_MODE) {
      // Restrict the message length to min(INT_MAX, 2^(8*(15-iv_len))-1) bytes.
      // TODO(osp) implement this check
      //          CHECK(iv_len >= 7 && iv_len <= 13);
      max_message_size_ = INT_MAX;
      if (iv_len == 12) max_message_size_ = 16777215;
      if (iv_len == 13) max_message_size_ = 65535;
    }
  }

  return true;
}

bool MGLCipherHostObject::CheckCCMMessageLength(int message_len) {
  // TODO(osp) Implement this check
  //      CHECK(EVP_CIPHER_CTX_mode(ctx_) == EVP_CIPH_CCM_MODE);

  if (message_len > max_message_size_) {
    //        THROW_ERR_CRYPTO_INVALID_MESSAGELEN(env());
    return false;
  }

  return true;
}

MGLCipherHostObject::~MGLCipherHostObject() {
  if (this->ctx_ != nullptr) {
    EVP_CIPHER_CTX_free(this->ctx_);
  }

  // TODO(osp) go over destructor
}
}  // namespace margelo
