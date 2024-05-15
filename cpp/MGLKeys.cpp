//
//  MGLCipherKeys.cpp
//  react-native-quick-crypto
//
//  Created by Oscar on 20.06.22.
//

#include "MGLKeys.h"

#include <jsi/jsi.h>
#include <openssl/bio.h>
#include <openssl/ec.h>

#include <algorithm>
#include <iostream>
#include <optional>
#include <utility>
#include <vector>

#ifdef ANDROID
#include "Cipher/MGLRsa.h"
#include "JSIUtils/MGLJSIMacros.h"
#include "JSIUtils/MGLJSIUtils.h"
#include "JSIUtils/MGLTypedArray.h"
#include "Utils/MGLUtils.h"
#include "webcrypto/crypto_ec.h"
#else
#include "MGLRsa.h"
#include "MGLJSIMacros.h"
#include "MGLJSIUtils.h"
#include "MGLTypedArray.h"
#include "MGLUtils.h"
#include "crypto_ec.h"
#endif

namespace margelo {
namespace jsi = facebook::jsi;

void GetKeyFormatAndTypeFromJs(AsymmetricKeyEncodingConfig* config,
                               jsi::Runtime& runtime, const jsi::Value* args,
                               unsigned int* offset,
                               KeyEncodingContext context) {
  // During key pair generation, it is possible not to specify a key encoding,
  // which will lead to a key object being returned.
  if (args[*offset].isUndefined()) {
    CHECK_EQ(context, kKeyContextGenerate);
    CHECK(args[*offset + 1].isUndefined());
    config->output_key_object_ = true;
  } else {
    config->output_key_object_ = false;

    // TODO(osp) implement check
    //    CHECK(args[*offset]->IsInt32());
    config->format_ = static_cast<PKFormatType>((int)args[*offset].getNumber());

    if (args[*offset + 1].isNumber()) {
      config->type_ =
          static_cast<PKEncodingType>((int)args[*offset + 1].getNumber());
    } else {
      CHECK(
          (context == kKeyContextInput && config->format_ == kKeyFormatPEM) ||
          (context == kKeyContextGenerate && config->format_ == kKeyFormatJWK));
      CHECK(args[*offset + 1].isUndefined());
      config->type_ = std::nullopt;
    }
  }

  *offset += 2;
}

ParseKeyResult TryParsePublicKey(
    EVPKeyPointer* pkey, const BIOPointer& bp, const char* name,
    const std::function<EVP_PKEY*(const unsigned char** p, long l)>& parse) {
  unsigned char* der_data;
  long der_len;

  // This skips surrounding data and decodes PEM to DER.
  if (PEM_bytes_read_bio(&der_data, &der_len, nullptr, name, bp.get(), nullptr,
                         nullptr) != 1) {
    return ParseKeyResult::kParseKeyNotRecognized;
  }

  // OpenSSL might modify the pointer, so we need to make a copy before parsing.
  const unsigned char* p = der_data;
  pkey->reset(parse(&p, der_len));
  OPENSSL_clear_free(der_data, der_len);

  return *pkey ? ParseKeyResult::kParseKeyOk : ParseKeyResult::kParseKeyFailed;
}

ParseKeyResult ParsePublicKeyPEM(EVPKeyPointer* pkey, const char* key_pem,
                                 int key_pem_len) {
  BIOPointer bp(BIO_new_mem_buf(const_cast<char*>(key_pem), key_pem_len));
  if (!bp) return ParseKeyResult::kParseKeyFailed;

  ParseKeyResult ret;

  // Try parsing as a SubjectPublicKeyInfo first.
  ret = TryParsePublicKey(pkey, bp, "PUBLIC KEY",
                          [](const unsigned char** p, long l) {
                            return d2i_PUBKEY(nullptr, p, l);
                          });

  if (ret != ParseKeyResult::kParseKeyNotRecognized) return ret;

  // Maybe it is PKCS#1.
  BIO_reset(bp.get());
  ret = TryParsePublicKey(pkey, bp, "RSA PUBLIC KEY",
                          [](const unsigned char** p, long l) {
                            return d2i_PublicKey(EVP_PKEY_RSA, nullptr, p, l);
                          });
  if (ret != ParseKeyResult::kParseKeyNotRecognized) return ret;

  // X.509 fallback.
  BIO_reset(bp.get());
  return TryParsePublicKey(
      pkey, bp, "CERTIFICATE", [](const unsigned char** p, long l) {
        X509Pointer x509(d2i_X509(nullptr, p, l));
        return x509 ? X509_get_pubkey(x509.get()) : nullptr;
      });
}

ParseKeyResult ParsePublicKey(EVPKeyPointer* pkey,
                              const PublicKeyEncodingConfig& config,
                              const char* key, size_t key_len) {
  if (config.format_ == kKeyFormatPEM) {
    return ParsePublicKeyPEM(pkey, key, key_len);
  } else {
    //    CHECK_EQ(config.format_, kKeyFormatDER);

    const unsigned char* p = reinterpret_cast<const unsigned char*>(key);
    if (config.type_.value() == kKeyEncodingPKCS1) {
      pkey->reset(d2i_PublicKey(EVP_PKEY_RSA, nullptr, &p, key_len));
    } else {
      //      CHECK_EQ(config.type_.ToChecked(), kKeyEncodingSPKI);
      pkey->reset(d2i_PUBKEY(nullptr, &p, key_len));
    }

    return *pkey ? ParseKeyResult::kParseKeyOk
                 : ParseKeyResult::kParseKeyFailed;
  }
}

bool IsASN1Sequence(const unsigned char* data, size_t size, size_t* data_offset,
                    size_t* data_size) {
  if (size < 2 || data[0] != 0x30) return false;

  if (data[1] & 0x80) {
    // Long form.
    size_t n_bytes = data[1] & ~0x80;
    if (n_bytes + 2 > size || n_bytes > sizeof(size_t)) return false;
    size_t length = 0;
    for (size_t i = 0; i < n_bytes; i++) length = (length << 8) | data[i + 2];
    *data_offset = 2 + n_bytes;
    *data_size = std::min(size - 2 - n_bytes, length);
  } else {
    // Short form.
    *data_offset = 2;
    *data_size = std::min<size_t>(size - 2, data[1]);
  }

  return true;
}

bool IsRSAPrivateKey(const unsigned char* data, size_t size) {
  // Both RSAPrivateKey and RSAPublicKey structures start with a SEQUENCE.
  size_t offset, len;
  if (!IsASN1Sequence(data, size, &offset, &len)) return false;

  // An RSAPrivateKey sequence always starts with a single-byte integer whose
  // value is either 0 or 1, whereas an RSAPublicKey starts with the modulus
  // (which is the product of two primes and therefore at least 4), so we can
  // decide the type of the structure based on the first three bytes of the
  // sequence.
  return len >= 3 && data[offset] == 2 && data[offset + 1] == 1 &&
         !(data[offset + 2] & 0xfe);
}

bool IsEncryptedPrivateKeyInfo(const unsigned char* data, size_t size) {
  // Both PrivateKeyInfo and EncryptedPrivateKeyInfo start with a SEQUENCE.
  size_t offset, len;
  if (!IsASN1Sequence(data, size, &offset, &len)) return false;

  // A PrivateKeyInfo sequence always starts with an integer whereas an
  // EncryptedPrivateKeyInfo starts with an AlgorithmIdentifier.
  return len >= 1 && data[offset] != 2;
}

ParseKeyResult ParsePrivateKey(EVPKeyPointer* pkey,
                               const PrivateKeyEncodingConfig& config,
                               const char* key, size_t key_len) {
  const ByteSource* passphrase = config.passphrase_.get();

  if (config.format_ == kKeyFormatPEM) {
    BIOPointer bio(BIO_new_mem_buf(key, (int)key_len));
    if (!bio) {
      return ParseKeyResult::kParseKeyFailed;
    }

    pkey->reset(PEM_read_bio_PrivateKey(bio.get(), nullptr, PasswordCallback,
                                        &passphrase));
  } else {
    CHECK_EQ(config.format_, kKeyFormatDER);

    if (!config.type_.has_value()) {
      throw new std::runtime_error("ParsePrivateKey key config has no type!");
    }

    if (config.type_.value() == kKeyEncodingPKCS1) {
      const unsigned char* p = reinterpret_cast<const unsigned char*>(key);
      pkey->reset(d2i_PrivateKey(EVP_PKEY_RSA, nullptr, &p, key_len));
    } else if (config.type_.value() == kKeyEncodingPKCS8) {
      BIOPointer bio(BIO_new_mem_buf(key, (int)key_len));
      if (!bio) return ParseKeyResult::kParseKeyFailed;

      if (IsEncryptedPrivateKeyInfo(reinterpret_cast<const unsigned char*>(key),
                                    key_len)) {
        pkey->reset(d2i_PKCS8PrivateKey_bio(bio.get(), nullptr,
                                            PasswordCallback, &passphrase));
      } else {
        PKCS8Pointer p8inf(d2i_PKCS8_PRIV_KEY_INFO_bio(bio.get(), nullptr));
        if (p8inf) pkey->reset(EVP_PKCS82PKEY(p8inf.get()));
      }
    } else {
      CHECK_EQ(config.type_.value(), kKeyEncodingSEC1);
      const unsigned char* p = reinterpret_cast<const unsigned char*>(key);
      pkey->reset(d2i_PrivateKey(EVP_PKEY_EC, nullptr, &p, key_len));
    }
  }

  // OpenSSL can fail to parse the key but still return a non-null pointer.
  unsigned long err = ERR_peek_error();  // NOLINT(runtime/int)
  auto reason = ERR_GET_REASON(err);
  // Per OpenSSL documentation PEM_R_NO_START_LINE signals all PEM certs have
  // been consumed and is a harmless error
  if (reason == PEM_R_NO_START_LINE && *pkey) {
    return ParseKeyResult::kParseKeyOk;
  }

  if (err != 0) pkey->reset();

  if (*pkey) {
    return ParseKeyResult::kParseKeyOk;
  }

  if (ERR_GET_LIB(err) == ERR_LIB_PEM) {
    if (reason == PEM_R_BAD_PASSWORD_READ && config.passphrase_.IsEmpty()) {
      return ParseKeyResult::kParseKeyNeedPassphrase;
    }
  }
  return ParseKeyResult::kParseKeyFailed;
}

OptionJSVariant BIOToStringOrBuffer(jsi::Runtime& rt, BIO* bio, PKFormatType format) {
  BUF_MEM* bptr;
  BIO_get_mem_ptr(bio, &bptr);
  if (format == kKeyFormatPEM) {
    // PEM is an ASCII format, so we will return it as a string.
    return JSVariant(std::string(bptr->data, bptr->length));
  } else {
    CHECK_EQ(format, kKeyFormatDER);
    // DER is binary, return it as a buffer.
    ByteSource::Builder out(bptr->length);
    memcpy(out.data<void>(), bptr->data, bptr->length);
    return std::move(out).release();
  }
}

OptionJSVariant WritePrivateKey(
    jsi::Runtime& runtime, EVP_PKEY* pkey,
    const PrivateKeyEncodingConfig& config) {
  BIOPointer bio(BIO_new(BIO_s_mem()));
  CHECK(bio);

  // If an empty string was passed as the passphrase, the ByteSource might
  // contain a null pointer, which OpenSSL will ignore, causing it to invoke its
  // default passphrase callback, which would block the thread until the user
  // manually enters a passphrase. We could supply our own passphrase callback
  // to handle this special case, but it is easier to avoid passing a null
  // pointer to OpenSSL.
  char* pass = nullptr;
  size_t pass_len = 0;
  if (!config.passphrase_.IsEmpty()) {
    pass = const_cast<char*>(config.passphrase_->data<char>());
    pass_len = config.passphrase_->size();
    if (pass == nullptr) {
      // OpenSSL will not actually dereference this pointer, so it can be any
      // non-null pointer. We cannot assert that directly, which is why we
      // intentionally use a pointer that will likely cause a segmentation fault
      // when dereferenced.
      //      CHECK_EQ(pass_len, 0);
      pass = reinterpret_cast<char*>(-1);
      //      CHECK_NE(pass, nullptr);
    }
  }

  bool err = false;
  PKEncodingType encoding_type;

  if (config.type_.has_value()) {
    encoding_type = config.type_.value();
  } else {
    // default for no value in std::option `config.type_`
    encoding_type = kKeyEncodingSEC1;
  }

  if (encoding_type == kKeyEncodingPKCS1) {
    // PKCS#1 is only permitted for RSA keys.
    //    CHECK_EQ(EVP_PKEY_id(pkey), EVP_PKEY_RSA);

    RsaPointer rsa(EVP_PKEY_get1_RSA(pkey));
    if (config.format_ == kKeyFormatPEM) {
      // Encode PKCS#1 as PEM.
      err = PEM_write_bio_RSAPrivateKey(bio.get(), rsa.get(), config.cipher_,
                                        reinterpret_cast<unsigned char*>(pass),
                                        pass_len, nullptr, nullptr) != 1;
    } else {
      // Encode PKCS#1 as DER. This does not permit encryption.
      CHECK_EQ(config.format_, kKeyFormatDER);
      CHECK_NULL(config.cipher_);
      err = i2d_RSAPrivateKey_bio(bio.get(), rsa.get()) != 1;
    }
  } else if (encoding_type == kKeyEncodingPKCS8) {
    if (config.format_ == kKeyFormatPEM) {
      // Encode PKCS#8 as PEM.
      err = PEM_write_bio_PKCS8PrivateKey(bio.get(), pkey, config.cipher_, pass,
                                          pass_len, nullptr, nullptr) != 1;
    } else {
      // Encode PKCS#8 as DER.
      CHECK_EQ(config.format_, kKeyFormatDER);
      err = i2d_PKCS8PrivateKey_bio(bio.get(), pkey, config.cipher_, pass,
                                    pass_len, nullptr, nullptr) != 1;
    }
  } else {
    CHECK_EQ(encoding_type, kKeyEncodingSEC1);

    // SEC1 is only permitted for EC keys.
    CHECK_EQ(EVP_PKEY_id(pkey), EVP_PKEY_EC);

    ECKeyPointer ec_key(EVP_PKEY_get1_EC_KEY(pkey));
    if (config.format_ == kKeyFormatPEM) {
      // Encode SEC1 as PEM.
      err = PEM_write_bio_ECPrivateKey(bio.get(),ec_key.get(), config.cipher_,
                                       reinterpret_cast<unsigned char*>(pass),
                                       pass_len, nullptr, nullptr) != 1;
    } else {
      // Encode SEC1 as DER. This does not permit encryption.
      CHECK_EQ(config.format_, kKeyFormatDER);
      // CHECK_NULL(config.cipher_);
      err = i2d_ECPrivateKey_bio(bio.get(), ec_key.get()) != 1;
    }
  }

  if (err) {
    throw jsi::JSError(runtime, "Failed to encode private key");
  }

  return BIOToStringOrBuffer(runtime, bio.get(), config.format_);
}

bool WritePublicKeyInner(EVP_PKEY* pkey, const BIOPointer& bio,
                         const PublicKeyEncodingConfig& config) {
  if (config.type_.has_value() && config.type_.value() == kKeyEncodingPKCS1) {
    // PKCS#1 is only valid for RSA keys.
    CHECK_EQ(EVP_PKEY_id(pkey), EVP_PKEY_RSA);
    RsaPointer rsa(EVP_PKEY_get1_RSA(pkey));
    if (config.format_ == kKeyFormatPEM) {
      // Encode PKCS#1 as PEM.
      return PEM_write_bio_RSAPublicKey(bio.get(), rsa.get()) == 1;
    } else {
      // Encode PKCS#1 as DER.
      CHECK_EQ(config.format_, kKeyFormatDER);
      return i2d_RSAPublicKey_bio(bio.get(), rsa.get()) == 1;
    }
  } else {
    //  CHECK_EQ(config.type_.ToChecked(), kKeyEncodingSPKI);
    if (config.format_ == kKeyFormatPEM) {
      // Encode SPKI as PEM.
      return PEM_write_bio_PUBKEY(bio.get(), pkey) == 1;
    } else {
      // Encode SPKI as DER.
      CHECK_EQ(config.format_, kKeyFormatDER);
      return i2d_PUBKEY_bio(bio.get(), pkey) == 1;
    }
  }
}

OptionJSVariant WritePublicKey(
    jsi::Runtime& runtime, EVP_PKEY* pkey,
    const PublicKeyEncodingConfig& config) {
  BIOPointer bio(BIO_new(BIO_s_mem()));
  CHECK(bio);

  if (!WritePublicKeyInner(pkey, bio, config)) {
    throw jsi::JSError(runtime, "Failed to encode public key");
  }

  return BIOToStringOrBuffer(runtime, bio.get(), config.format_);
}

jsi::Value ExportJWKSecretKey(jsi::Runtime &rt,
                              std::shared_ptr<KeyObjectData> key,
                              jsi::Object &result) {
  CHECK_EQ(key->GetKeyType(), kKeyTypeSecret);

  std::string key_data = EncodeBase64(key->GetSymmetricKey(), true);

  result.setProperty(rt, "kty", "oct");
  result.setProperty(rt, "k", key_data);
  return std::move(result);
}

std::shared_ptr<KeyObjectData> ImportJWKSecretKey(jsi::Runtime &rt,
                                                  jsi::Object &jwk) {
  std::string key = jwk
    .getProperty(rt, "k")
    .asString(rt)
    .utf8(rt);

  // TODO: when adding tests, trap errors like below (i.e. no `k` property, undefined)
  //  Local<Value> key;
  //  if (!jwk->Get(env->context(), env->jwk_k_string()).ToLocal(&key) ||
  //      !key->IsString()) {
  //    THROW_ERR_CRYPTO_INVALID_JWK(env, "Invalid JWK secret key format");
  //    return std::shared_ptr<KeyObjectData>();
  //  }

  ByteSource key_data = ByteSource::FromEncodedString(rt, key, encoding::BASE64URL);
  if (key_data.size() > INT_MAX) {
    throw jsi::JSError(rt, "Invalid crypto key length");
    return std::shared_ptr<KeyObjectData>();
  }

  return KeyObjectData::CreateSecret(std::move(key_data));
}

jsi::Value ExportJWKAsymmetricKey(jsi::Runtime &rt,
                                  std::shared_ptr<KeyObjectData> key,
                                  jsi::Object &target,
                                  bool handleRsaPss) {
  switch (EVP_PKEY_id(key->GetAsymmetricKey().get())) {
    case EVP_PKEY_RSA_PSS: {
      if (handleRsaPss) return ExportJWKRsaKey(rt, key, target);
      break;
    }
    case EVP_PKEY_RSA: return ExportJWKRsaKey(rt, key, target);
    case EVP_PKEY_EC: return ExportJWKEcKey(rt, key, target);
    // case EVP_PKEY_ED25519:
    //   // Fall through
    // case EVP_PKEY_ED448:
    //   // Fall through
    // case EVP_PKEY_X25519:
    //   // Fall through
    // case EVP_PKEY_X448: return ExportJWKEdKey(rt, key, target);
  }
  throw jsi::JSError(rt, "Unsupported JWK asymmetric key type");
}

std::shared_ptr<KeyObjectData> ImportJWKAsymmetricKey(jsi::Runtime &rt,
                                                      jsi::Object &jwk,
                                                      std::string kty,
                                                      jsi::Value &namedCurve) {
  if (kty.compare("RSA") == 0) {
    return ImportJWKRsaKey(rt, jwk);
  } else if (kty.compare("EC") == 0) {
    return ImportJWKEcKey(rt, jwk, namedCurve);
  }

  throw jsi::JSError(rt, "%s is not a supported JWK key type", kty);
  return std::shared_ptr<KeyObjectData>();
}

jsi::Value GetSecretKeyDetail(jsi::Runtime &rt,
                              std::shared_ptr<KeyObjectData> key) {
  jsi::Object target = jsi::Object(rt);
  // For the secret key detail, all we care about is the length,
  // converted to bits.
  size_t length = key->GetSymmetricKeySize() * CHAR_BIT;
  target.setProperty(rt, "length", static_cast<double>(length));
  return std::move(target);
}

jsi::Value GetAsymmetricKeyDetail(jsi::Runtime &rt,
                                  std::shared_ptr<KeyObjectData> key) {
  switch (EVP_PKEY_id(key->GetAsymmetricKey().get())) {
    case EVP_PKEY_RSA:
      // Fall through
    case EVP_PKEY_RSA_PSS: return GetRsaKeyDetail(rt, key);
    // case EVP_PKEY_DSA: return GetDsaKeyDetail(env, key);
    case EVP_PKEY_EC: return GetEcKeyDetail(rt, key);
    // case EVP_PKEY_DH: return GetDhKeyDetail(env, key);
  }
  throw jsi::JSError(rt, "Invalid Key Type");
  return false;
}

ManagedEVPPKey::ManagedEVPPKey(EVPKeyPointer&& pkey) : pkey_(std::move(pkey)) {}

ManagedEVPPKey::ManagedEVPPKey(const ManagedEVPPKey& that) { *this = that; }

ManagedEVPPKey& ManagedEVPPKey::operator=(const ManagedEVPPKey& that) {
  //  Mutex::ScopedLock lock(*that.mutex_);

  pkey_.reset(that.get());

  if (pkey_) EVP_PKEY_up_ref(pkey_.get());

  //  mutex_ = that.mutex_;

  return *this;
}

ManagedEVPPKey::operator bool() const { return !!pkey_; }

EVP_PKEY* ManagedEVPPKey::get() const { return pkey_.get(); }

// Mutex* ManagedEVPPKey::mutex() const {
//  return mutex_.get();
//}
//
// void ManagedEVPPKey::MemoryInfo(MemoryTracker* tracker) const {
//  tracker->TrackFieldWithSize("pkey",
//                              !pkey_ ? 0 : kSizeOf_EVP_PKEY +
//                              size_of_private_key() +
//                              size_of_public_key());
//}

size_t ManagedEVPPKey::size_of_private_key() const {
 size_t len = 0;
 return (pkey_ && EVP_PKEY_get_raw_private_key(pkey_.get(), nullptr, &len) == 1)
  ? len : 0;
}

size_t ManagedEVPPKey::size_of_public_key() const {
 size_t len = 0;
 return (pkey_ && EVP_PKEY_get_raw_public_key(pkey_.get(), nullptr, &len) == 1)
  ? len : 0;
}

jsi::Value ExportJWKInner(jsi::Runtime &rt,
                          std::shared_ptr<KeyObjectData> key,
                          jsi::Object &result,
                          bool handleRsaPss) {
  switch (key->GetKeyType()) {
    case kKeyTypeSecret:
      return ExportJWKSecretKey(rt, key, result);
    case kKeyTypePublic:
      // Fall through
    case kKeyTypePrivate:
      return ExportJWKAsymmetricKey(rt, key, result, handleRsaPss);
    default:
      throw jsi::JSError(rt, "unreachable code in ExportJWKInner");
  }
}

OptionJSVariant ManagedEVPPKey::ToEncodedPublicKey(jsi::Runtime& rt,
                                                   ManagedEVPPKey key,
                                                   const PublicKeyEncodingConfig& config) {
  if (!key) return {};
  if (config.output_key_object_) {
    // Note that this has the downside of containing sensitive data of the
    // private key.
    auto data = KeyObjectData::CreateAsymmetric(kKeyTypePublic, std::move(key));
    auto out = KeyObjectHandle::Create(rt, data);
    return JSVariant(out);
  } else
  if (config.format_ == kKeyFormatJWK) {
    throw std::runtime_error("ToEncodedPublicKey 2 (JWK) not implemented from node");
    // std::shared_ptr<KeyObjectData> data =
    // KeyObjectData::CreateAsymmetric(kKeyTypePublic, std::move(key));
    // *out = Object::New(env->isolate());
    // return ExportJWKInner(env, data, *out, false);
  }

  return WritePublicKey(rt, key.get(), config);
}

OptionJSVariant ManagedEVPPKey::ToEncodedPrivateKey(jsi::Runtime& rt,
                                                    ManagedEVPPKey key,
                                                    const PrivateKeyEncodingConfig& config) {
  if (!key) return {};
  if (config.output_key_object_) {
    auto data = KeyObjectData::CreateAsymmetric(kKeyTypePrivate, std::move(key));
    auto out = KeyObjectHandle::Create(rt, data);
    return JSVariant(out);
  } else
  if (config.format_ == kKeyFormatJWK) {
    throw std::runtime_error("ToEncodedPrivateKey 2 (JWK) not implemented from node");
    // std::shared_ptr<KeyObjectData> data =
    // KeyObjectData::CreateAsymmetric(kKeyTypePrivate, std::move(key));
    // *out = Object::New(env->isolate());
    // return ExportJWKInner(env, data, *out, false);
  }

  return WritePrivateKey(rt, key.get(), config);
}

NonCopyableMaybe<PrivateKeyEncodingConfig>
ManagedEVPPKey::GetPrivateKeyEncodingFromJs(jsi::Runtime& runtime,
                                            const jsi::Value* arguments,
                                            unsigned int* offset,
                                            KeyEncodingContext context) {
  PrivateKeyEncodingConfig result;
  GetKeyFormatAndTypeFromJs(&result, runtime, arguments, offset, context);

  if (result.output_key_object_) {
    if (context != kKeyContextInput) (*offset)++;
  } else {
    bool needs_passphrase = false;
    if (context != kKeyContextInput) {
      if (arguments[*offset].isString()) {
        auto cipher_name = arguments[*offset].getString(runtime).utf8(runtime);
        result.cipher_ = EVP_get_cipherbyname(cipher_name.c_str());
        if (result.cipher_ == nullptr) {
          throw jsi::JSError(runtime, "Unknown cipher");
        }
        needs_passphrase = true;
      } else {
        //        CHECK(args[*offset]->IsNullOrUndefined());
        result.cipher_ = nullptr;
      }
      (*offset)++;
    }

    if (CheckIsArrayBuffer(runtime, arguments[*offset])) {
      //      CHECK_IMPLIES(context != kKeyContextInput, result.cipher_ !=
      //      nullptr); ArrayBufferOrViewContents<char>
      //      passphrase(arguments[*offset]);
      jsi::ArrayBuffer passphrase =
          arguments[*offset].asObject(runtime).getArrayBuffer(runtime);
      if (!CheckSizeInt32(runtime, passphrase)) {
        throw jsi::JSError(runtime, "passphrase is too long");
      }

      result.passphrase_ = NonCopyableMaybe<ByteSource>(
          ToNullTerminatedByteSource(runtime, passphrase));
    } else {
      if (needs_passphrase &&
          (arguments[*offset].isNull() || arguments[*offset].isUndefined())) {
        throw jsi::JSError(
            runtime, "passphrase is null or undefined but it is required");
      }
    }
  }

  (*offset)++;
  return NonCopyableMaybe<PrivateKeyEncodingConfig>(std::move(result));
}

PublicKeyEncodingConfig ManagedEVPPKey::GetPublicKeyEncodingFromJs(
    jsi::Runtime& runtime, const jsi::Value* arguments, unsigned int* offset,
    KeyEncodingContext context) {
  PublicKeyEncodingConfig result;
  GetKeyFormatAndTypeFromJs(&result, runtime, arguments, offset, context);
  return result;
}

ManagedEVPPKey ManagedEVPPKey::GetPrivateKeyFromJs(jsi::Runtime& runtime,
                                                   const jsi::Value* args,
                                                   unsigned int* offset,
                                                   bool allow_key_object) {
  if (args[*offset].isString() ||
      args[*offset].asObject(runtime).isArrayBuffer(runtime)) {
    ByteSource key = ByteSource::FromStringOrBuffer(runtime, args[*offset]);
    (*offset)++;
    NonCopyableMaybe<PrivateKeyEncodingConfig> config =
        GetPrivateKeyEncodingFromJs(runtime, args, offset, kKeyContextInput);
    if (config.IsEmpty()) return ManagedEVPPKey();

    EVPKeyPointer pkey;
    ParseKeyResult ret =
        ParsePrivateKey(&pkey, config.Release(), key.data<char>(), key.size());
    return GetParsedKey(runtime, std::move(pkey), ret,
                        "Failed to read private key");
  } else {
    //    CHECK(args[*offset]->IsObject() && allow_key_object);
    //    KeyObjectHandle* key;
    //    ASSIGN_OR_RETURN_UNWRAP(&key, args[*offset].As<Object>(),
    //    ManagedEVPPKey()); CHECK_EQ(key->Data()->GetKeyType(),
    //    kKeyTypePrivate);
    //    (*offset) += 4;
    //    return key->Data()->GetAsymmetricKey();
    throw jsi::JSError(runtime, "KeyObject are not currently supported");
  }
}

ManagedEVPPKey ManagedEVPPKey::GetPublicOrPrivateKeyFromJs(
    jsi::Runtime& runtime, const jsi::Value* args, unsigned int* offset) {
  if (args[*offset].asObject(runtime).isArrayBuffer(runtime)) {
    auto dataArrayBuffer =
        args[(*offset)++].asObject(runtime).getArrayBuffer(runtime);

    if (!CheckSizeInt32(runtime, dataArrayBuffer)) {
      throw jsi::JSError(runtime, "data is too big");
    }

    NonCopyableMaybe<PrivateKeyEncodingConfig> config_ =
        GetPrivateKeyEncodingFromJs(runtime, args, offset, kKeyContextInput);
    if (config_.IsEmpty()) return ManagedEVPPKey();

    ParseKeyResult ret;
    PrivateKeyEncodingConfig config = config_.Release();
    EVPKeyPointer pkey;
    if (config.format_ == kKeyFormatPEM) {
      // For PEM, we can easily determine whether it is a public or private
      // key by looking for the respective PEM tags.
      ret = ParsePublicKeyPEM(&pkey, (const char*)dataArrayBuffer.data(runtime),
                              (int)dataArrayBuffer.size(runtime));
      if (ret == ParseKeyResult::kParseKeyNotRecognized) {
        ret = ParsePrivateKey(&pkey, config,
                              (const char*)dataArrayBuffer.data(runtime),
                              (int)dataArrayBuffer.size(runtime));
      }
    } else {
      // For DER, the type determines how to parse it. SPKI, PKCS#8 and SEC1
      // are easy, but PKCS#1 can be a public key or a private key.
      bool is_public;
      switch (config.type_.value()) {
        case kKeyEncodingPKCS1:
          is_public = !IsRSAPrivateKey(reinterpret_cast<const unsigned char*>(
                                           dataArrayBuffer.data(runtime)),
                                       dataArrayBuffer.size(runtime));
          break;
        case kKeyEncodingSPKI:
          is_public = true;
          break;
        case kKeyEncodingPKCS8:
        case kKeyEncodingSEC1:
          is_public = false;
          break;
        default:
          throw jsi::JSError(runtime, "Invalid key encoding type");
      }

      if (is_public) {
        ret = ParsePublicKey(&pkey, config,
                             (const char*)dataArrayBuffer.data(runtime),
                             dataArrayBuffer.size(runtime));
      } else {
        ret = ParsePrivateKey(&pkey, config,
                              (const char*)dataArrayBuffer.data(runtime),
                              dataArrayBuffer.size(runtime));
      }
    }

    return ManagedEVPPKey::GetParsedKey(runtime, std::move(pkey), ret,
                                        "Failed to read asymmetric key");
  } else {
    throw jsi::JSError(
        runtime, "public encrypt only supports ArrayBuffer at the moment");
    //    CHECK(args[*offset]->IsObject());
    //    KeyObjectHandle* key =
    //    Unwrap<KeyObjectHandle>(args[*offset].As<Object>());
    //    CHECK_NOT_NULL(key);
    //    CHECK_NE(key->Data()->GetKeyType(), kKeyTypeSecret);
    //    (*offset) += 4;
    //    return key->Data()->GetAsymmetricKey();
  }
}

ManagedEVPPKey ManagedEVPPKey::GetParsedKey(jsi::Runtime& runtime,
                                            EVPKeyPointer&& pkey,
                                            ParseKeyResult ret,
                                            const char* default_msg) {
  switch (ret) {
    case ParseKeyResult::kParseKeyOk:
      //       CHECK(pkey);
      break;
    case ParseKeyResult::kParseKeyNeedPassphrase:
      throw jsi::JSError(runtime, "Passphrase required for encrypted key");
      break;
    default:
      throw jsi::JSError(runtime, default_msg);
  }

  return ManagedEVPPKey(std::move(pkey));
}

KeyObjectData::KeyObjectData(ByteSource symmetric_key)
: key_type_(KeyType::kKeyTypeSecret),
  symmetric_key_(std::move(symmetric_key)),
  symmetric_key_len_(symmetric_key_.size()),
  asymmetric_key_() {}

KeyObjectData::KeyObjectData(KeyType type,
                             const ManagedEVPPKey& pkey)
: key_type_(type),
  symmetric_key_(),
  symmetric_key_len_(0),
  asymmetric_key_{pkey} {}

std::shared_ptr<KeyObjectData> KeyObjectData::CreateSecret(ByteSource key)
{
  CHECK(key);
  return std::shared_ptr<KeyObjectData>(new KeyObjectData(std::move(key)));
}

std::shared_ptr<KeyObjectData> KeyObjectData::CreateAsymmetric(
  KeyType key_type,
  const ManagedEVPPKey& pkey
) {
  CHECK(pkey);
  return std::shared_ptr<KeyObjectData>(new KeyObjectData(key_type, pkey));
}

KeyType KeyObjectData::GetKeyType() const {
  return key_type_;
}

ManagedEVPPKey KeyObjectData::GetAsymmetricKey() const {
  CHECK_NE(key_type_, kKeyTypeSecret);
  return asymmetric_key_;
}

/** Gets the symmetric key value
 * binary data stored in string, tolerates \0 characters
 */
std::string KeyObjectData::GetSymmetricKey() const {
  CHECK_EQ(key_type_, kKeyTypeSecret);
  return symmetric_key_.ToString();
}

size_t KeyObjectData::GetSymmetricKeySize() const {
  CHECK_EQ(key_type_, kKeyTypeSecret);
  return symmetric_key_len_;
}


jsi::Value KeyObjectHandle::get(
  jsi::Runtime &rt,
  const jsi::PropNameID &propNameID) {
    auto name = propNameID.utf8(rt);

    if (name == "export") {
      return this->Export(rt);
    } else if (name == "exportJwk") {
      return this->ExportJWK(rt);
    } else if (name == "initECRaw") {
      return this-> InitECRaw(rt);
    } else if (name == "init") {
      return this->Init(rt);
    } else if (name == "initJwk") {
      return this->InitJWK(rt);
    } else if (name == "keyDetail") {
      return this->GetKeyDetail(rt);
    }

    return {};
}

// v8::Local<v8::Function> KeyObjectHandle::Initialize(Environment* env) {
//   Local<Function> templ = env->crypto_key_object_handle_constructor();
//   if (!templ.IsEmpty()) {
//     return templ;
//   }
//   Local<FunctionTemplate> t = env->NewFunctionTemplate(New);
//   t->InstanceTemplate()->SetInternalFieldCount(
//                                                KeyObjectHandle::kInternalFieldCount);
//   t->Inherit(BaseObject::GetConstructorTemplate(env));
//
//   env->SetProtoMethod(t, "init", Init);
//   env->SetProtoMethodNoSideEffect(t, "getSymmetricKeySize",
//                                   GetSymmetricKeySize);
//   env->SetProtoMethodNoSideEffect(t, "getAsymmetricKeyType",
//                                   GetAsymmetricKeyType);
//   env->SetProtoMethod(t, "export", Export);
//   env->SetProtoMethod(t, "exportJwk", ExportJWK);
//   env->SetProtoMethod(t, "initECRaw", InitECRaw);
//   env->SetProtoMethod(t, "initEDRaw", InitEDRaw);
//   env->SetProtoMethod(t, "initJwk", InitJWK);
//   env->SetProtoMethod(t, "keyDetail", GetKeyDetail);
//   env->SetProtoMethod(t, "equals", Equals);
//
//   auto function = t->GetFunction(env->context()).ToLocalChecked();
//   env->set_crypto_key_object_handle_constructor(function);
//   return function;
// }
//
// void KeyObjectHandle::RegisterExternalReferences(
//                                                  ExternalReferenceRegistry*
//                                                  registry) {
//   registry->Register(New);
//   registry->Register(Init);
//   registry->Register(GetSymmetricKeySize);
//   registry->Register(GetAsymmetricKeyType);
//   registry->Register(Export);
//   registry->Register(ExportJWK);
//   registry->Register(InitECRaw);
//   registry->Register(InitEDRaw);
//   registry->Register(InitJWK);
//   registry->Register(GetKeyDetail);
//   registry->Register(Equals);
// }

KeyObjectHandle* KeyObjectHandle::Create(jsi::Runtime &rt,
                                   std::shared_ptr<KeyObjectData> data) {
  KeyObjectHandle* handle = new KeyObjectHandle();
  handle->data_ = data;
  return handle;
}

const std::shared_ptr<KeyObjectData>& KeyObjectHandle::Data() {
  return this->data_;
}
//
// void KeyObjectHandle::New(const FunctionCallbackInfo<Value>& args) {
//   CHECK(args.IsConstructCall());
//   Environment* env = Environment::GetCurrent(args);
//   new KeyObjectHandle(env, args.This());
// }
//
// KeyObjectHandle::KeyObjectHandle(Environment* env,
//                                  Local<Object> wrap)
//: BaseObject(env, wrap) {
//  MakeWeak();
//}
//

jsi::Value KeyObjectHandle::Init(jsi::Runtime &rt) {
  return HOSTFN("init", 2) {
    CHECK(args[0].isNumber());
    KeyType type = static_cast<KeyType>((int32_t)args[0].asNumber());

    unsigned int offset;
    ManagedEVPPKey pkey;

    switch (type) {
      case kKeyTypeSecret: {
        // CHECK_EQ(args.Length(), 2);

        ByteSource key = ByteSource::FromStringOrBuffer(rt, args[1]);
        this->data_ = KeyObjectData::CreateSecret(std::move(key));
        break;
      }
      case kKeyTypePublic: {
        // CHECK_EQ(args.Length(), 5);

        offset = 1;
        pkey = ManagedEVPPKey::GetPublicOrPrivateKeyFromJs(rt, args, &offset);
        if (!pkey)
          return false;
        this->data_ = KeyObjectData::CreateAsymmetric(type, pkey);
        break;
      }
      case kKeyTypePrivate: {
        // CHECK_EQ(args.Length(), 5);

        offset = 1;
        pkey = ManagedEVPPKey::GetPrivateKeyFromJs(rt, args, &offset, false);
        if (!pkey)
          return false;
        this->data_ = KeyObjectData::CreateAsymmetric(type, pkey);
        break;
      }
      default:
        throw jsi::JSError(rt, "invalid keytype for init(): " + std::to_string(type));
    }

    return true;
  });
}

jsi::Value KeyObjectHandle::InitJWK(jsi::Runtime &rt) {
  return HOSTFN("initJwk", 2) {
    // The argument must be a JavaScript object that we will inspect
    // to get the JWK properties from.
    jsi::Object jwk = jsi::Object(jsi::Value(rt, args[0]).asObject(rt));
    jsi::Value namedCurve;
    if (count == 2)
      namedCurve = jsi::Value(rt, args[1]);

    // Step one, Secret key or not?
    std::string kty = jwk
      .getProperty(rt, "kty")
      .asString(rt)
      .utf8(rt);

    if (kty.compare("oct") == 0) {
      // Secret key
      this->data_ = ImportJWKSecretKey(rt, jwk);
      if (!this->data_) {
        // ImportJWKSecretKey is responsible for throwing an appropriate error
        return jsi::Value::undefined();
      }
    } else {
      this->data_ = ImportJWKAsymmetricKey(rt, jwk, kty, namedCurve);
      if (!this->data_) {
        // ImportJWKAsymmetricKey is responsible for throwing an appropriate
        // error
       return jsi::Value::undefined();
      }
    }

    return static_cast<int>(this->data_->GetKeyType());
  });
}

jsi::Value KeyObjectHandle::InitECRaw(jsi::Runtime &rt) {
  return HOSTFN("initECRaw", 2) {
      CHECK(args[0].isString());
      std::string curveName = args[0].asString(rt).utf8(rt);
      int id = OBJ_txt2nid(curveName.c_str());
      ECKeyPointer eckey(EC_KEY_new_by_curve_name(id));
      if (!eckey) {
          return false;
      }

      CHECK(args[1].isObject());
      if (!args[1].getObject(rt).isArrayBuffer(rt)) {
        throw jsi::JSError(rt,
                          "KeyObjectHandle::InitECRaw: second argument "
                          "has to be of type ArrayBuffer!");
      }
      auto buf = args[1].asObject(rt).getArrayBuffer(rt);

      const EC_GROUP* group = EC_KEY_get0_group(eckey.get());
      ECPointPointer pub(ECDH::BufferToPoint(rt, group, buf));

      if (!pub ||
          !eckey ||
          !EC_KEY_set_public_key(eckey.get(), pub.get())) {
          return false;
      }

      EVPKeyPointer pkey(EVP_PKEY_new());
      if (!EVP_PKEY_assign_EC_KEY(pkey.get(), eckey.get())) {
          return false;
      }

      eckey.release();  // Release ownership of the key

      this->data_ =
      KeyObjectData::CreateAsymmetric(
                                      kKeyTypePublic,
                                      ManagedEVPPKey(std::move(pkey)));

      return true;
  });
}

// void KeyObjectHandle::InitEDRaw(const FunctionCallbackInfo<Value>& args) {
//  Environment* env = Environment::GetCurrent(args);
//  KeyObjectHandle* key;
//  ASSIGN_OR_RETURN_UNWRAP(&key, args.Holder());
//
//  CHECK(args[0]->IsString());
//  Utf8Value name(env->isolate(), args[0]);
//
//  ArrayBufferOrViewContents<unsigned char> key_data(args[1]);
//  KeyType type = static_cast<KeyType>(args[2].As<Int32>()->Value());
//
//  MarkPopErrorOnReturn mark_pop_error_on_return;
//
//  typedef EVP_PKEY* (*new_key_fn)(int, ENGINE*, const unsigned char*,
//  size_t); new_key_fn fn = type == kKeyTypePrivate ?
//  EVP_PKEY_new_raw_private_key : EVP_PKEY_new_raw_public_key;
//
//  int id = GetOKPCurveFromName(*name);
//
//  switch (id) {
//    case EVP_PKEY_X25519:
//    case EVP_PKEY_X448:
//    case EVP_PKEY_ED25519:
//    case EVP_PKEY_ED448: {
//      EVPKeyPointer pkey(fn(id, nullptr, key_data.data(), key_data.size()));
//      if (!pkey)
//        return args.GetReturnValue().Set(false);
//      key->data_ =
//      KeyObjectData::CreateAsymmetric(
//                                      type,
//                                      ManagedEVPPKey(std::move(pkey)));
//      CHECK(key->data_);
//      break;
//    }
//    default:
//      throw jsi::JSError(rt, "unreachable code in InitEDRaw");
//  }
//
//  args.GetReturnValue().Set(true);
//}
//
// void KeyObjectHandle::Equals(const FunctionCallbackInfo<Value>& args) {
//  KeyObjectHandle* self_handle;
//  KeyObjectHandle* arg_handle;
//  ASSIGN_OR_RETURN_UNWRAP(&self_handle, args.Holder());
//  ASSIGN_OR_RETURN_UNWRAP(&arg_handle, args[0].As<Object>());
//  std::shared_ptr<KeyObjectData> key = self_handle->Data();
//  std::shared_ptr<KeyObjectData> key2 = arg_handle->Data();
//
//  KeyType key_type = key->GetKeyType();
//  CHECK_EQ(key_type, key2->GetKeyType());
//
//  bool ret;
//  switch (key_type) {
//    case kKeyTypeSecret: {
//      size_t size = key->GetSymmetricKeySize();
//      if (size == key2->GetSymmetricKeySize()) {
//        ret = CRYPTO_memcmp(
//                            key->GetSymmetricKey(),
//                            key2->GetSymmetricKey(),
//                            size) == 0;
//      } else {
//        ret = false;
//      }
//      break;
//    }
//    case kKeyTypePublic:
//    case kKeyTypePrivate: {
//      EVP_PKEY* pkey = key->GetAsymmetricKey().get();
//      EVP_PKEY* pkey2 = key2->GetAsymmetricKey().get();
//#if OPENSSL_VERSION_MAJOR >= 3
//      int ok = EVP_PKEY_eq(pkey, pkey2);
//#else
//      int ok = EVP_PKEY_cmp(pkey, pkey2);
//#endif
//      if (ok == -2) {
//        Environment* env = Environment::GetCurrent(args);
//        return THROW_ERR_CRYPTO_UNSUPPORTED_OPERATION(env);
//      }
//      ret = ok == 1;
//      break;
//    }
//    default:
//        throw jsi::JSError(rt, "unreachable code in Equals");
//  }
//
//  args.GetReturnValue().Set(ret);
//}

jsi::Value KeyObjectHandle::GetKeyDetail(jsi::Runtime &rt) {
  return HOSTFN("keyDetail", 0) {
    std::shared_ptr<KeyObjectData> data = this->Data();

    switch (data->GetKeyType()) {
      case kKeyTypeSecret:
        return GetSecretKeyDetail(rt, data);
        break;
      case kKeyTypePublic:
        // Fall through
      case kKeyTypePrivate:
        return GetAsymmetricKeyDetail(rt, data);
        break;
      default:
        throw jsi::JSError(rt, "unreachable code in GetKeyDetail");
    }
  });
}

// Local<Value> KeyObjectHandle::GetAsymmetricKeyType() const {
//  const ManagedEVPPKey& key = data_->GetAsymmetricKey();
//  switch (EVP_PKEY_id(key.get())) {
//    case EVP_PKEY_RSA:
//      return env()->crypto_rsa_string();
//    case EVP_PKEY_RSA_PSS:
//      return env()->crypto_rsa_pss_string();
//    case EVP_PKEY_DSA:
//      return env()->crypto_dsa_string();
//    case EVP_PKEY_DH:
//      return env()->crypto_dh_string();
//    case EVP_PKEY_EC:
//      return env()->crypto_ec_string();
//    case EVP_PKEY_ED25519:
//      return env()->crypto_ed25519_string();
//    case EVP_PKEY_ED448:
//      return env()->crypto_ed448_string();
//    case EVP_PKEY_X25519:
//      return env()->crypto_x25519_string();
//    case EVP_PKEY_X448:
//      return env()->crypto_x448_string();
//    default:
//      return Undefined(env()->isolate());
//  }
//}
//
// void KeyObjectHandle::GetAsymmetricKeyType(
//                                           const
//                                           FunctionCallbackInfo<Value>&
//                                           args) {
//  KeyObjectHandle* key;
//  ASSIGN_OR_RETURN_UNWRAP(&key, args.Holder());
//
//  args.GetReturnValue().Set(key->GetAsymmetricKeyType());
//}
//
// void KeyObjectHandle::GetSymmetricKeySize(
//                                          const FunctionCallbackInfo<Value>&
//                                          args) {
//  KeyObjectHandle* key;
//  ASSIGN_OR_RETURN_UNWRAP(&key, args.Holder());
//  args.GetReturnValue().Set(
//                            static_cast<uint32_t>(key->Data()->GetSymmetricKeySize()));
//}

jsi::Value KeyObjectHandle::Export(jsi::Runtime &rt) {
  return HOSTFN("export", 2) {
    KeyType type = this->data_->GetKeyType();
    OptionJSVariant result;
    if (type == kKeyTypeSecret) {
      result = this->ExportSecretKey(rt);
    }
    else if (type == kKeyTypePublic) {
      unsigned int offset = 0;
      PublicKeyEncodingConfig config =
          ManagedEVPPKey::GetPublicKeyEncodingFromJs(
              rt, args, &offset, kKeyContextExport);
      result = this->ExportPublicKey(rt, config);
    }
    else if (type == kKeyTypePrivate) {
      unsigned int offset = 0;
      NonCopyableMaybe<PrivateKeyEncodingConfig> config =
          ManagedEVPPKey::GetPrivateKeyEncodingFromJs(
              rt, args, &offset, kKeyContextExport);
      if (!config.IsEmpty()) {
        result = this->ExportPrivateKey(rt, config.Release());
      }
    }
    return toJSI(rt, result);
  });
}

OptionJSVariant KeyObjectHandle::ExportSecretKey(jsi::Runtime &rt) const {
  std::string ret = data_->GetSymmetricKey();
  return JSVariant(ByteSource::FromString(ret));
}

OptionJSVariant KeyObjectHandle::ExportPublicKey(
    jsi::Runtime& rt,
    const PublicKeyEncodingConfig& config) const {
  return WritePublicKey(rt,
    data_->GetAsymmetricKey().get(),
    config);
}

OptionJSVariant KeyObjectHandle::ExportPrivateKey(
    jsi::Runtime &rt,
    const PrivateKeyEncodingConfig& config) const {
  return WritePrivateKey(rt,
    data_->GetAsymmetricKey().get(),
    config);
}

jsi::Value KeyObjectHandle::ExportJWK(jsi::Runtime &rt) {
  return HOSTFN("exportJwk", 2) {
    CHECK(args[0].isObject());
    CHECK(args[1].isBool());
    std::shared_ptr<KeyObjectData> data = this->Data();
    jsi::Object result = args[0].asObject(rt);
    return ExportJWKInner(rt, data, result, args[1].asBool());
  });
}

// void NativeKeyObject::Initialize(Environment* env, Local<Object> target) {
//  env->SetMethod(target, "createNativeKeyObjectClass",
//                 NativeKeyObject::CreateNativeKeyObjectClass);
//}
//
// void NativeKeyObject::RegisterExternalReferences(
//                                                 ExternalReferenceRegistry*
//                                                 registry) {
//  registry->Register(NativeKeyObject::CreateNativeKeyObjectClass);
//  registry->Register(NativeKeyObject::New);
//}
//
// void NativeKeyObject::New(const FunctionCallbackInfo<Value>& args) {
//  Environment* env = Environment::GetCurrent(args);
//  CHECK_EQ(args.Length(), 1);
//  CHECK(args[0]->IsObject());
//  KeyObjectHandle* handle = Unwrap<KeyObjectHandle>(args[0].As<Object>());
//  new NativeKeyObject(env, args.This(), handle->Data());
//}
//
// void NativeKeyObject::CreateNativeKeyObjectClass(
//                                                 const
//                                                 FunctionCallbackInfo<Value>&
//                                                 args) {
//  Environment* env = Environment::GetCurrent(args);
//
//  CHECK_EQ(args.Length(), 1);
//  Local<Value> callback = args[0];
//  CHECK(callback->IsFunction());
//
//  Local<FunctionTemplate> t =
//  env->NewFunctionTemplate(NativeKeyObject::New);
//  t->InstanceTemplate()->SetInternalFieldCount(
//                                               KeyObjectHandle::kInternalFieldCount);
//  t->Inherit(BaseObject::GetConstructorTemplate(env));
//
//  Local<Value> ctor;
//  if (!t->GetFunction(env->context()).ToLocal(&ctor))
//    return;
//
//  Local<Value> recv = Undefined(env->isolate());
//  Local<Value> ret_v;
//  if (!callback.As<Function>()->Call(
//                                     env->context(), recv, 1,
//                                     &ctor).ToLocal(&ret_v)) {
//                                       return;
//                                     }
//  Local<Array> ret = ret_v.As<Array>();
//  if (!ret->Get(env->context(), 1).ToLocal(&ctor)) return;
//  env->set_crypto_key_object_secret_constructor(ctor.As<Function>());
//  if (!ret->Get(env->context(), 2).ToLocal(&ctor)) return;
//  env->set_crypto_key_object_public_constructor(ctor.As<Function>());
//  if (!ret->Get(env->context(), 3).ToLocal(&ctor)) return;
//  env->set_crypto_key_object_private_constructor(ctor.As<Function>());
//  args.GetReturnValue().Set(ret);
//}
//
// BaseObjectPtr<BaseObject>
// NativeKeyObject::KeyObjectTransferData::Deserialize(
//                                                        Environment* env,
//                                                        Local<Context>
//                                                        context,
//                                                        std::unique_ptr<worker::TransferData>
//                                                        self) {
//  if (context != env->context()) {
//    THROW_ERR_MESSAGE_TARGET_CONTEXT_UNAVAILABLE(env);
//    return {};
//  }
//
//  Local<Value> handle;
//  if (!KeyObjectHandle::Create(env, data_).ToLocal(&handle))
//    return {};
//
//  Local<Function> key_ctor;
//  Local<Value> arg = FIXED_ONE_BYTE_STRING(env->isolate(),
//                                           "internal/crypto/keys");
//  if (env->native_module_require()->
//      Call(context, Null(env->isolate()), 1, &arg).IsEmpty()) {
//    return {};
//  }
//  switch (data_->GetKeyType()) {
//    case kKeyTypeSecret:
//      key_ctor = env->crypto_key_object_secret_constructor();
//      break;
//    case kKeyTypePublic:
//      key_ctor = env->crypto_key_object_public_constructor();
//      break;
//    case kKeyTypePrivate:
//      key_ctor = env->crypto_key_object_private_constructor();
//      break;
//    default:
//      CHECK(false);
//  }
//
//  Local<Value> key;
//  if (!key_ctor->NewInstance(context, 1, &handle).ToLocal(&key))
//    return {};
//
//  return
//  BaseObjectPtr<BaseObject>(Unwrap<KeyObjectHandle>(key.As<Object>()));
//}
//
// BaseObject::TransferMode NativeKeyObject::GetTransferMode() const {
//  return BaseObject::TransferMode::kCloneable;
//}
//
// std::unique_ptr<worker::TransferData> NativeKeyObject::CloneForMessaging()
// const {
//  return std::make_unique<KeyObjectTransferData>(handle_data_);
//}
//
// WebCryptoKeyExportStatus PKEY_SPKI_Export(
//                                          KeyObjectData* key_data,
//                                          ByteSource* out) {
//  CHECK_EQ(key_data->GetKeyType(), kKeyTypePublic);
//  ManagedEVPPKey m_pkey = key_data->GetAsymmetricKey();
//  Mutex::ScopedLock lock(*m_pkey.mutex());
//  BIOPointer bio(BIO_new(BIO_s_mem()));
//  CHECK(bio);
//  if (!i2d_PUBKEY_bio(bio.get(), m_pkey.get()))
//    return WebCryptoKeyExportStatus::FAILED;
//
//  *out = ByteSource::FromBIO(bio);
//  return WebCryptoKeyExportStatus::OK;
//}
//
// WebCryptoKeyExportStatus PKEY_PKCS8_Export(
//                                           KeyObjectData* key_data,
//                                           ByteSource* out) {
//  CHECK_EQ(key_data->GetKeyType(), kKeyTypePrivate);
//  ManagedEVPPKey m_pkey = key_data->GetAsymmetricKey();
//  Mutex::ScopedLock lock(*m_pkey.mutex());
//
//  BIOPointer bio(BIO_new(BIO_s_mem()));
//  CHECK(bio);
//  PKCS8Pointer p8inf(EVP_PKEY2PKCS8(m_pkey.get()));
//  if (!i2d_PKCS8_PRIV_KEY_INFO_bio(bio.get(), p8inf.get()))
//    return WebCryptoKeyExportStatus::FAILED;
//
//  *out = ByteSource::FromBIO(bio);
//  return WebCryptoKeyExportStatus::OK;
//}

//  void RegisterExternalReferences(ExternalReferenceRegistry * registry) {
//    KeyObjectHandle::RegisterExternalReferences(registry);
//  }

}  // namespace margelo
