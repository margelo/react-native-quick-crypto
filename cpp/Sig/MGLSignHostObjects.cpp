#include "MGLSignHostObjects.h"

#include <openssl/evp.h>

#include <optional>

#include "MGLKeys.h"
#ifdef ANDROID
#include "JSIUtils/MGLJSIUtils.h"
#include "JSIUtils/MGLTypedArray.h"
#include "Utils/MGLUtils.h"
#else
#include "MGLJSIUtils.h"
#include "MGLTypedArray.h"
#include "MGLUtils.h"
#endif

namespace margelo {

bool ValidateDSAParameters(EVP_PKEY* key) {
  /* Validate DSA2 parameters from FIPS 186-4 */
#if OPENSSL_VERSION_MAJOR >= 3
  if (EVP_default_properties_is_fips_enabled(nullptr) &&
      EVP_PKEY_DSA == EVP_PKEY_base_id(key)) {
#else
  if (FIPS_mode() && EVP_PKEY_DSA == EVP_PKEY_base_id(key)) {
#endif
    const DSA* dsa = EVP_PKEY_get0_DSA(key);
    const BIGNUM* p;
    DSA_get0_pqg(dsa, &p, nullptr, nullptr);
    size_t L = BN_num_bits(p);
    const BIGNUM* q;
    DSA_get0_pqg(dsa, nullptr, &q, nullptr);
    size_t N = BN_num_bits(q);

    return (L == 1024 && N == 160) || (L == 2048 && N == 224) ||
           (L == 2048 && N == 256) || (L == 3072 && N == 256);
  }

  return true;
}

bool ApplyRSAOptions(const ManagedEVPPKey& pkey, EVP_PKEY_CTX* pkctx,
                     int padding, std::optional<int> salt_len) {
  if (EVP_PKEY_id(pkey.get()) == EVP_PKEY_RSA ||
      EVP_PKEY_id(pkey.get()) == EVP_PKEY_RSA2 ||
      EVP_PKEY_id(pkey.get()) == EVP_PKEY_RSA_PSS) {
    if (EVP_PKEY_CTX_set_rsa_padding(pkctx, padding) <= 0) return false;
    if (padding == RSA_PKCS1_PSS_PADDING && salt_len.has_value()) {
      if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkctx, salt_len.value()) <= 0)
        return false;
    }
  }

  return true;
}

std::optional<jsi::Value> Node_SignFinal(jsi::Runtime& runtime,
                                         EVPMDPointer&& mdctx,
                                         const ManagedEVPPKey& pkey,
                                         int padding,
                                         std::optional<int> pss_salt_len) {
  unsigned char m[EVP_MAX_MD_SIZE];
  unsigned int m_len;

  if (!EVP_DigestFinal_ex(mdctx.get(), m, &m_len)) return {};

  int signed_sig_len = EVP_PKEY_size(pkey.get());
  CHECK_GE(signed_sig_len, 0);
  size_t sig_len = static_cast<size_t>(signed_sig_len);

  MGLTypedArray<MGLTypedArrayKind::Uint8Array> sig(runtime, sig_len);

  EVPKeyCtxPointer pkctx(EVP_PKEY_CTX_new(pkey.get(), nullptr));
  if (pkctx && EVP_PKEY_sign_init(pkctx.get()) &&
      ApplyRSAOptions(pkey, pkctx.get(), padding, pss_salt_len) &&
      EVP_PKEY_CTX_set_signature_md(pkctx.get(), EVP_MD_CTX_md(mdctx.get())) &&
      EVP_PKEY_sign(
          pkctx.get(),
          static_cast<unsigned char*>(sig.getBuffer(runtime).data(runtime)),
          &sig_len, m, m_len)) {
    CHECK_LE(sig_len, sig.size(runtime));

    // do this bits need to be trimmed? I think so
    //    if (sig_len == 0)
    //      sig = ArrayBuffer::NewBackingStore(env->isolate(), 0);
    //    else
    //      sig = BackingStore::Reallocate(env->isolate(), std::move(sig),
    //      sig_len);
    return sig;
  }

  return {};
}

//  int GetDefaultSignPadding(const ManagedEVPPKey& m_pkey) {
//    return EVP_PKEY_id(m_pkey.get()) == EVP_PKEY_RSA_PSS ?
//    RSA_PKCS1_PSS_PADDING : RSA_PKCS1_PADDING;
//  }
//
unsigned int GetBytesOfRS(const ManagedEVPPKey& pkey) {
  int bits, base_id = EVP_PKEY_base_id(pkey.get());

  if (base_id == EVP_PKEY_DSA) {
    const DSA* dsa_key = EVP_PKEY_get0_DSA(pkey.get());
    // Both r and s are computed mod q, so their width is limited by that of
    bits = BN_num_bits(DSA_get0_q(dsa_key));
  } else if (base_id == EVP_PKEY_EC) {
    const EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(pkey.get());
    const EC_GROUP* ec_group = EC_KEY_get0_group(ec_key);
    bits = EC_GROUP_order_bits(ec_group);
  } else {
    return kNoDsaSignature;
  }

  return (bits + 7) / 8;
}

 bool ExtractP1363(const unsigned char* sig_data,
                   unsigned char* out,
                   size_t len,
                   size_t n) {
  ECDSASigPointer asn1_sig(d2i_ECDSA_SIG(nullptr,
  &sig_data, len)); if (!asn1_sig)
    return false;

  const BIGNUM* pr = ECDSA_SIG_get0_r(asn1_sig.get());
  const BIGNUM* ps = ECDSA_SIG_get0_s(asn1_sig.get());

  return BN_bn2binpad(pr, out, n) > 0 && BN_bn2binpad(ps,
  out + n, n) > 0;
}

//  // Returns the maximum size of each of the integers (r, s) of the DSA signature.
//  std::unique_ptr<BackingStore> ConvertSignatureToP1363(Environment* env,
//                                                        const ManagedEVPPKey&
//                                                        pkey,
//                                                        std::unique_ptr<BackingStore>&&
//                                                        signature) {
//    unsigned int n = GetBytesOfRS(pkey);
//    if (n == kNoDsaSignature)
//      return std::move(signature);
//
//    std::unique_ptr<BackingStore> buf;
//    {
//      NoArrayBufferZeroFillScope no_zero_fill_scope(env->isolate_data());
//      buf = ArrayBuffer::NewBackingStore(env->isolate(), 2 * n);
//    }
//    if (!ExtractP1363(static_cast<unsigned char*>(signature->Data()),
//                      static_cast<unsigned char*>(buf->Data()),
//                      signature->ByteLength(), n))
//      return std::move(signature);
//
//    return buf;
//  }

 // Returns the maximum size of each of the integers (r, s) of the DSA signature.
 ByteSource ConvertSignatureToP1363(const ManagedEVPPKey& pkey,
                                    const ByteSource& signature) {
  unsigned int n = GetBytesOfRS(pkey);
  if (n == kNoDsaSignature)
    return ByteSource();

  const unsigned char* sig_data =
  signature.data<unsigned char>();

  ByteSource::Builder out(n * 2);
  memset(out.data<void>(), 0, n * 2);

  if (!ExtractP1363(sig_data,
  out.data<unsigned char>(),
  signature.size(), n))
    return ByteSource();

  return std::move(out).release();
}

ByteSource ConvertSignatureToDER(const ManagedEVPPKey& pkey, ByteSource&& out) {
  unsigned int n = GetBytesOfRS(pkey);
  if (n == kNoDsaSignature) return std::move(out);

  const unsigned char* sig_data = out.data<unsigned char>();

  if (out.size() != 2 * n) return ByteSource();

  ECDSASigPointer asn1_sig(ECDSA_SIG_new());
  CHECK(asn1_sig);
  BIGNUM* r = BN_new();
  CHECK_NOT_NULL(r);
  BIGNUM* s = BN_new();
  CHECK_NOT_NULL(s);
  CHECK_EQ(r, BN_bin2bn(sig_data, n, r));
  CHECK_EQ(s, BN_bin2bn(sig_data + n, n, s));
  CHECK_EQ(1, ECDSA_SIG_set0(asn1_sig.get(), r, s));

  unsigned char* data = nullptr;
  int len = i2d_ECDSA_SIG(asn1_sig.get(), &data);

  if (len <= 0) return ByteSource();

  CHECK_NOT_NULL(data);

  return ByteSource::Allocated(reinterpret_cast<char*>(data), len);
}

//  void CheckThrow(Environment* env, SignBase::Error error) {
//    HandleScope scope(env->isolate());
//
//    switch (error) {
//      case SignBase::Error::kSignUnknownDigest:
//        return THROW_ERR_CRYPTO_INVALID_DIGEST(env);
//
//      case SignBase::Error::kSignNotInitialised:
//        return THROW_ERR_CRYPTO_INVALID_STATE(env, "Not initialised");
//
//      case SignBase::Error::kSignMalformedSignature:
//        return THROW_ERR_CRYPTO_OPERATION_FAILED(env, "Malformed signature");
//
//      case SignBase::Error::kSignInit:
//      case SignBase::Error::kSignUpdate:
//      case SignBase::Error::kSignPrivateKey:
//      case SignBase::Error::kSignPublicKey:
//      {
//        unsigned long err = ERR_get_error();  // NOLINT(runtime/int)
//        if (err)
//          return ThrowCryptoError(env, err);
//        switch (error) {
//          case SignBase::Error::kSignInit:
//            return THROW_ERR_CRYPTO_OPERATION_FAILED(env,
//                                                     "EVP_SignInit_ex
//                                                     failed");
//          case SignBase::Error::kSignUpdate:
//            return THROW_ERR_CRYPTO_OPERATION_FAILED(env,
//                                                     "EVP_SignUpdate failed");
//          case SignBase::Error::kSignPrivateKey:
//            return THROW_ERR_CRYPTO_OPERATION_FAILED(env,
//                                                     "PEM_read_bio_PrivateKey
//                                                     failed");
//          case SignBase::Error::kSignPublicKey:
//            return THROW_ERR_CRYPTO_OPERATION_FAILED(env,
//                                                     "PEM_read_bio_PUBKEY
//                                                     failed");
//          default:
//            ABORT();
//        }
//      }
//
//      case SignBase::Error::kSignOk:
//        return;
//    }
//  }

 bool IsOneShot(const ManagedEVPPKey& key) {
   switch (EVP_PKEY_id(key.get())) {
     case EVP_PKEY_ED25519:
     case EVP_PKEY_ED448:
       return true;
     default:
       return false;
   }
 }

 bool UseP1363Encoding(const ManagedEVPPKey& key,
                       const DSASigEnc& dsa_encoding) {
   switch (EVP_PKEY_id(key.get())) {
     case EVP_PKEY_EC:
     case EVP_PKEY_DSA:
       return dsa_encoding == kSigEncP1363;
     default:
       return false;
   }
 }

SignBase::SignResult SignBase::SignFinal(jsi::Runtime& runtime,
                                         const ManagedEVPPKey& pkey,
                                         int padding,
                                         std::optional<int>& salt_len,
                                         DSASigEnc dsa_sig_enc) {
  if (!mdctx_) return SignResult(kSignNotInitialised);

  EVPMDPointer mdctx = std::move(mdctx_);

  if (!ValidateDSAParameters(pkey.get())) return SignResult(kSignPrivateKey);

  std::optional<jsi::Value> buffer =
      Node_SignFinal(runtime, std::move(mdctx), pkey, padding, salt_len);
  Error error = buffer.has_value() ? kSignOk : kSignPrivateKey;
  // TODO(osp) enable this
  //  if (error == kSignOk && dsa_sig_enc == kSigEncP1363) {
  //    buffer = ConvertSignatureToP1363(env(), pkey, std::move(buffer));
  //    CHECK_NOT_NULL(buffer->Data());
  //  }
  return SignResult(error, std::move(buffer.value()));
}

SignBase::Error SignBase::VerifyFinal(const ManagedEVPPKey& pkey,
                                      const ByteSource& sig, int padding,
                                      std::optional<int>& saltlen,
                                      bool* verify_result) {
  if (!mdctx_) return kSignNotInitialised;

  unsigned char m[EVP_MAX_MD_SIZE];
  unsigned int m_len;
  *verify_result = false;
  EVPMDPointer mdctx = std::move(mdctx_);

  if (!EVP_DigestFinal_ex(mdctx.get(), m, &m_len)) return kSignPublicKey;

  EVPKeyCtxPointer pkctx(EVP_PKEY_CTX_new(pkey.get(), nullptr));
  if (pkctx && EVP_PKEY_verify_init(pkctx.get()) > 0 &&
      ApplyRSAOptions(pkey, pkctx.get(), padding, saltlen) &&
      EVP_PKEY_CTX_set_signature_md(pkctx.get(), EVP_MD_CTX_md(mdctx.get())) >
          0) {
    const unsigned char* s = sig.data<unsigned char>();
    const int r = EVP_PKEY_verify(pkctx.get(), s, sig.size(), m, m_len);
    *verify_result = r == 1;
  }

  return kSignOk;
}

SignBase::SignBase(std::shared_ptr<react::CallInvoker> jsCallInvoker,
                   std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue)
    : MGLSmartHostObject(jsCallInvoker, workerQueue) {}

MGLSignHostObject::MGLSignHostObject(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue)
    : SignBase(jsCallInvoker, workerQueue) {
  InstallMethods(kModeSign);
}

MGLVerifyHostObject::MGLVerifyHostObject(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue)
    : SignBase(jsCallInvoker, workerQueue) {
  InstallMethods(kModeVerify);
}

int GetDefaultSignPadding(const ManagedEVPPKey& m_pkey) {
  return EVP_PKEY_id(m_pkey.get()) == EVP_PKEY_RSA_PSS ? RSA_PKCS1_PSS_PADDING
                                                       : RSA_PKCS1_PADDING;
}

void SignBase::InstallMethods(mode mode) {
  this->fields.push_back(buildPair(
      "init", JSIF([=]) {
        if (count != 1 || !arguments[0].isString()) {
          throw jsi::JSError(runtime, "init requires algorithm param");
          return {};
        }

        std::string sign_type = arguments[0].asString(runtime).utf8(runtime);
        CHECK_NULL(mdctx_);

        // Historically, "dss1" and "DSS1" were DSA aliases for SHA-1
        // exposed through the public API.
        if (sign_type.compare("dss1") == 0 || sign_type.compare("DSS1") == 0) {
          sign_type = "SHA1";
        }

        const EVP_MD* md = EVP_get_digestbyname(sign_type.c_str());
        if (md == nullptr) return jsi::Value((int)kSignUnknownDigest);

        mdctx_.reset(EVP_MD_CTX_new());
        if (!mdctx_ || !EVP_DigestInit_ex(mdctx_.get(), md, nullptr)) {
          mdctx_.reset();
          return jsi::Value((int)kSignInit);
        }

        return jsi::Value((int)kSignOk);
      }));

  this->fields.push_back(buildPair(
      "update", JSIF([=]) {
        if (count != 1) {
          throw jsi::JSError(runtime, "update requires 2 arguments");
        }

        if (!arguments[0].isObject() ||
            !arguments[0].asObject(runtime).isArrayBuffer(runtime)) {
          throw jsi::JSError(
              runtime, "First argument (data) needs to be an array buffer");
        }

        auto data = arguments[0].asObject(runtime).getArrayBuffer(runtime);

        if (!CheckSizeInt32(runtime, data)) {
          throw jsi::JSError(runtime, "data is too large");
        }

        if (mdctx_ == nullptr) return (int)kSignNotInitialised;
        if (!EVP_DigestUpdate(mdctx_.get(), data.data(runtime),
                              data.size(runtime)))
          return (int)kSignUpdate;
        return (int)kSignOk;
      }));

  if (mode == kModeSign) {
    this->fields.push_back(buildPair(
        "sign", JSIF([=]) {
          unsigned int offset = 0;
          ManagedEVPPKey key = ManagedEVPPKey::GetPrivateKeyFromJs(
              runtime, arguments, &offset, true);
          if (!key) {
            return {};
          }

          int padding = GetDefaultSignPadding(key);
          if (!arguments[offset].isUndefined()) {
            // TODO(osp) need to add a check for int32
            CHECK(arguments[offset].isNumber());
            padding = static_cast<int>(arguments[offset].asNumber());
          }

          std::optional<int> salt_len;
          if (!arguments[offset + 1].isUndefined()) {
            // TODO(osp) add check for int32
            CHECK(arguments[offset + 1].isNumber());
            salt_len = static_cast<int>(arguments[offset + 1].asNumber());
          }

          // TODO(osp) add check for int32
          CHECK(arguments[offset + 2].isNumber());
          DSASigEnc dsa_sig_enc = static_cast<DSASigEnc>(
              static_cast<int>(arguments[offset + 2].asNumber()));

          SignResult ret =
              this->SignFinal(runtime, key, padding, salt_len, dsa_sig_enc);

          if (ret.error != kSignOk) {
            throw jsi::JSError(runtime, "Error signing");
          }

          return std::move(ret.signature.value());
        }));
  } else {
    this->fields.push_back(buildPair(
        "verify", JSIF([=]) {
          //      Verify* verify;
          //      ASSIGN_OR_RETURN_UNWRAP(&verify, args.Holder());

          unsigned int offset = 0;
          ManagedEVPPKey pkey = ManagedEVPPKey::GetPublicOrPrivateKeyFromJs(
              runtime, arguments, &offset);
          if (!pkey) {
            return {};
          }

          jsi::ArrayBuffer hbuf =
              arguments[offset].asObject(runtime).getArrayBuffer(runtime);
          if (!CheckSizeInt32(runtime, hbuf)) {
            throw jsi::JSError(runtime, "buffer is too big");
          }

          int padding = GetDefaultSignPadding(pkey);
          if (!arguments[offset + 1].isUndefined()) {
            CHECK(arguments[offset + 1].isNumber());
            padding = static_cast<int>(arguments[offset + 1].asNumber());
          }

          std::optional<int> salt_len;
          if (!arguments[offset + 2].isUndefined()) {
            // TODO(osp) add check for int32
            CHECK(arguments[offset + 2].isNumber());
            salt_len = static_cast<int>(arguments[offset + 2].asNumber());
          }

          // TODO(osp) add check for int32
          CHECK(arguments[offset + 3].isNumber());
          DSASigEnc dsa_sig_enc = static_cast<DSASigEnc>(
              static_cast<int>(arguments[offset + 3].asNumber()));

          ByteSource signature = ArrayBufferToByteSource(runtime, hbuf);
          if (dsa_sig_enc == kSigEncP1363) {
            signature = ConvertSignatureToDER(
                pkey, ArrayBufferToByteSource(runtime, hbuf));
            if (signature.data() == nullptr) {
              throw jsi::JSError(runtime, "kSignMalformedSignature");
            }
            //          return crypto::CheckThrow(env,
            //          Error::kSignMalformedSignature);
          }

          bool verify_result;
          Error err = this->VerifyFinal(pkey, signature, padding, salt_len,
                                        &verify_result);
          if (err != kSignOk) {
            throw jsi::JSError(runtime, "Error on verify");
          }

          return verify_result;
        }));
  }
}

SubtleSignVerify::SubtleSignVerify(std::shared_ptr<react::CallInvoker> jsCallInvoker,
                                   std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue)
    : MGLSmartHostObject(jsCallInvoker, workerQueue)
{
  this->fields.push_back(buildPair(
      "signVerify", JSIF([=]) {
        auto params = this->GetParamsFromJS(runtime, arguments);
        ByteSource out = this->DoSignVerify(runtime, params);
        return this->EncodeOutput(runtime, params, out);
      }));
};

// SignConfiguration::SignConfiguration(SignConfiguration&& other) noexcept
//: job_mode(other.job_mode),
// mode(other.mode),
// key(std::move(other.key)),
// data(std::move(other.data)),
// signature(std::move(other.signature)),
// digest(other.digest),
// flags(other.flags),
// padding(other.padding),
// salt_length(other.salt_length),
// dsa_encoding(other.dsa_encoding) {}
//
// SignConfiguration& SignConfiguration::operator=(
//                                                 SignConfiguration&& other)
//                                                 noexcept {
//                                                   if (&other == this) return
//                                                   *this;
//                                                   this->~SignConfiguration();
//                                                   return *new (this)
//                                                   SignConfiguration(std::move(other));
//                                                 }
//
// void SignConfiguration::MemoryInfo(MemoryTracker* tracker) const {
//   tracker->TrackField("key", key);
//   if (job_mode == kCryptoJobAsync) {
//     tracker->TrackFieldWithSize("data", data.size());
//     tracker->TrackFieldWithSize("signature", signature.size());
//   }
// }

SignConfiguration SubtleSignVerify::GetParamsFromJS(jsi::Runtime &rt,
                                                   const jsi::Value *args) {
  SignConfiguration params;
  unsigned int offset = 0;

  // mode (sign/verify)
  params.mode = static_cast<SignConfiguration::Mode>((int)args[offset].getNumber());
  offset++;

  // key
  ManagedEVPPKey key;
  unsigned int keyParamOffset = offset;
  if (params.mode == SignConfiguration::kVerify) {
    key = ManagedEVPPKey::GetPublicOrPrivateKeyFromJs(rt, args, &keyParamOffset);
  } else {
    key = ManagedEVPPKey::GetPrivateKeyFromJs(rt, args, &keyParamOffset, true);
  }
  if (!key) {
    return params;
  }
  params.key = key;
  offset = 5;

  // data
  ByteSource data = ByteSource::FromStringOrBuffer(rt, args[offset]);
  if (data.size() > INT_MAX) {
    throw jsi::JSError(rt, "data is too big (> int32)");
    return params;
  }
  params.data = std::move(data);
  offset++;

  // digest
  if (args[offset].isString()) {
    std::string digest = args[offset].asString(rt).utf8(rt);
    params.digest = EVP_get_digestbyname(digest.c_str());
    if (params.digest == nullptr) {
      throw jsi::JSError(rt, "invalid digest");
      return params;
    }
  }
  offset++;

  // salt length
  if (CheckIsInt32(args[offset])) {
    params.flags |= SignConfiguration::kHasSaltLength;
    params.salt_length = args[offset].asNumber();
  }
  offset++;

  // padding
  if (CheckIsInt32(args[offset])) {
    params.flags |= SignConfiguration::kHasPadding;
    params.padding = args[offset].asNumber();

  }
  offset++;

  // dsa encoding
  if (args[offset].isNumber()) {
    params.dsa_encoding =
    static_cast<DSASigEnc>(args[offset].asNumber());
    if (params.dsa_encoding != kSigEncDER &&
        params.dsa_encoding != kSigEncP1363) {
      throw jsi::JSError(rt, "invalid signature encoding");
      return params;
    }
  }
  offset++;

  // signature
  if (params.mode == SignConfiguration::kVerify) {
    ByteSource signature = ByteSource::FromStringOrBuffer(rt, args[offset]);
    if (signature.size() > INT_MAX) {
      throw jsi::JSError(rt, "signature is too big (> int32)");
      return params;
    }
    // If this is an EC key (assuming ECDSA) we need to convert the
    // the signature from WebCrypto format into DER format...
    ManagedEVPPKey m_pkey = params.key;
    // Mutex::ScopedLock lock(*m_pkey.mutex());
    if (UseP1363Encoding(m_pkey, params.dsa_encoding)) {
      params.signature =
      ConvertSignatureToDER(m_pkey, std::move(signature));
    } else {
      params.signature = std::move(signature);
    }
  }

  return params;
}

ByteSource SubtleSignVerify::DoSignVerify(jsi::Runtime &rt,
                                          const SignConfiguration &params) {
  ByteSource out;

  EVPMDPointer context(EVP_MD_CTX_new());
  EVP_PKEY_CTX* ctx = nullptr;

  switch (params.mode) {
    case SignConfiguration::kSign:
      if (!EVP_DigestSignInit(
                              context.get(),
                              &ctx,
                              params.digest,
                              nullptr,
                              params.key.get())) {
        throw jsi::JSError(rt, "EVP_DigestSignInit failed");
      }
      break;
    case SignConfiguration::kVerify:
      if (!EVP_DigestVerifyInit(
                                context.get(),
                                &ctx,
                                params.digest,
                                nullptr,
                                params.key.get())) {
        throw jsi::JSError(rt, "EVP_DigestVerifyInit failed");
      }
      break;
  }

  int padding = params.flags & SignConfiguration::kHasPadding
  ? params.padding
  : GetDefaultSignPadding(params.key);

  std::optional<int> salt_length = params.flags & SignConfiguration::kHasSaltLength
  ? std::optional(params.salt_length) : std::nullopt;

  if (!ApplyRSAOptions(params.key,
                       ctx,
                       padding,
                       salt_length)) {
    throw jsi::JSError(rt, "PEM_read_bio_PrivateKey failed");
  }

  switch (params.mode) {
    case SignConfiguration::kSign: {
      if (IsOneShot(params.key)) {
        size_t len;
        if (!EVP_DigestSign(
                            context.get(),
                            nullptr,
                            &len,
                            params.data.data<unsigned char>(),
                            params.data.size())) {
          throw jsi::JSError(rt, "PEM_read_bio_PrivateKey failed");
        }
        ByteSource::Builder buf(len);
        if (!EVP_DigestSign(context.get(),
                            buf.data<unsigned char>(),
                            &len,
                            params.data.data<unsigned char>(),
                            params.data.size())) {
          throw jsi::JSError(rt, "PEM_read_bio_PrivateKey failed");
        }
        out = std::move(buf).release(len);
      } else {
        size_t len;
        if (!EVP_DigestSignUpdate(
                                  context.get(),
                                  params.data.data<unsigned char>(),
                                  params.data.size()) ||
            !EVP_DigestSignFinal(context.get(), nullptr, &len)) {
          throw jsi::JSError(rt, "PEM_read_bio_PrivateKey failed");
        }
        ByteSource::Builder buf(len);
        if (!EVP_DigestSignFinal(
                                 context.get(), buf.data<unsigned char>(),
                                 &len)) {
          throw jsi::JSError(rt, "PEM_read_bio_PrivateKey failed");
        }

        if (UseP1363Encoding(params.key, params.dsa_encoding)) {
          out = ConvertSignatureToP1363(params.key,
                                        std::move(buf).release());
        } else {
          out = std::move(buf).release(len);
        }
      }
      break;
    }
    case SignConfiguration::kVerify: {
      ByteSource::Builder buf(1);
      buf.data<char>()[0] = 0;
      if (EVP_DigestVerify(
                           context.get(),
                           params.signature.data<unsigned char>(),
                           params.signature.size(),
                           params.data.data<unsigned char>(),
                           params.data.size()) == 1) {
                             buf.data<char>()[0] = 1;
                           }
      out = std::move(buf).release();
    }
  }

  return out;
}

jsi::Value SubtleSignVerify::EncodeOutput(jsi::Runtime &rt,
                                          const SignConfiguration &params,
                                          ByteSource &out) {
  JSVariant result;
  switch (params.mode) {
    case SignConfiguration::kSign:
      result = JSVariant(std::move(out));
      break;
    case SignConfiguration::kVerify:
      result = JSVariant(out.data<char>()[0] == 1);
      break;
    default:
      throw jsi::JSError(rt, "unreachable code in SubtleSignVerify::EncodeOutput");
  }
  return result;
}

}  // namespace margelo
