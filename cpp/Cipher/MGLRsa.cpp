//
//  MGLRsa.cpp
//  react-native-quick-crypto
//
//  Created by Oscar on 22.06.22.
//

#include "MGLRsa.h"
#ifdef ANDROID
#include "JSIUtils/MGLJSIMacros.h"
#else
#include "MGLJSIMacros.h"
#endif

#include <string>
#include <utility>

namespace margelo {

namespace jsi = facebook::jsi;

EVPKeyCtxPointer setup(std::shared_ptr<RsaKeyPairGenConfig> config) {
  EVPKeyCtxPointer ctx(EVP_PKEY_CTX_new_id(
      config->variant == kvRSA_PSS ? EVP_PKEY_RSA_PSS : EVP_PKEY_RSA,
      nullptr));

  if (EVP_PKEY_keygen_init(ctx.get()) <= 0) return EVPKeyCtxPointer();

  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), config->modulus_bits) <= 0) {
    return EVPKeyCtxPointer();
  }

  // 0x10001 is the default RSA exponent.
  if (config->exponent != 0x10001) {
    BignumPointer bn(BN_new());
    //    CHECK_NOT_NULL(bn.get());
    BN_set_word(bn.get(), config->exponent);
    // EVP_CTX accepts ownership of bn on success.
    if (EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx.get(), bn.get()) <= 0) {
      return EVPKeyCtxPointer();
    }

    bn.release();
  }

  if (config->variant == kvRSA_PSS) {
    if (config->md != nullptr &&
        EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx.get(), config->md) <= 0) {
      return EVPKeyCtxPointer();
    }

    // TODO(tniessen): This appears to only be necessary in OpenSSL 3, while
    // OpenSSL 1.1.1 behaves as recommended by RFC 8017 and defaults the MGF1
    // hash algorithm to the RSA-PSS hashAlgorithm. Remove this code if the
    // behavior of OpenSSL 3 changes.
    const EVP_MD* mgf1_md = config->mgf1_md;
    if (mgf1_md == nullptr && config->md != nullptr) {
      mgf1_md = config->md;
    }

    if (mgf1_md != nullptr &&
        EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(ctx.get(), mgf1_md) <= 0) {
      return EVPKeyCtxPointer();
    }

    int saltlen = config->saltlen;
    if (saltlen < 0 && config->md != nullptr) {
      saltlen = EVP_MD_size(config->md);
    }

    if (saltlen >= 0 &&
        EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx.get(), saltlen) <= 0) {
      return EVPKeyCtxPointer();
    }
  }

  return ctx;
}

RsaKeyPairGenConfig prepareRsaKeyGenConfig(jsi::Runtime& runtime,
                                           const jsi::Value* arguments) {
  RsaKeyPairGenConfig config = RsaKeyPairGenConfig();

  // This is a funky one: depending on which encryption scheme you are
  // using, there is a variable number of arguments that will need to be
  // parsed, therefore this pointer will be used by the internal functions
  // as they go reading the arguments based on the selected scheme. I
  // tried to keep as close to the node implementation to make future
  // debugging easier
  unsigned int offset = 0;

  // TODO(osp)
  //    CHECK(args[*offset]->IsUint32());  // Variant
  //    CHECK(args[*offset + 1]->IsUint32());  // Modulus bits
  //    CHECK(args[*offset + 2]->IsUint32());  // Exponent
  config.variant =
      static_cast<KeyVariant>((int)arguments[offset].asNumber());

  // TODO(osp)
  //    CHECK_IMPLIES(params->params.variant != kvRSA_PSS,
  //                  args.Length() == 10);
  //    CHECK_IMPLIES(params->params.variant == kvRSA_PSS,
  //                  args.Length() == 13);
  config.modulus_bits =
      static_cast<unsigned int>(arguments[offset + 1].asNumber());
  config.exponent = static_cast<unsigned int>(arguments[offset + 2].asNumber());

  offset += 3;

  if (config.variant == kvRSA_PSS) {
    if (!arguments[offset].isUndefined()) {
      // TODO(osp) CHECK(string)
      config.md = EVP_get_digestbyname(
          arguments[offset].asString(runtime).utf8(runtime).c_str());

      if (config.md == nullptr) {
        throw jsi::JSError(runtime, "invalid digest");
      }
    }

    if (!arguments[offset + 1].isUndefined()) {
      // TODO(osp) CHECK(string)
      config.mgf1_md = EVP_get_digestbyname(
          arguments[offset + 1].asString(runtime).utf8(runtime).c_str());

      if (config.mgf1_md == nullptr) {
        throw jsi::JSError(runtime, "invalid digest");
      }
    }

    if (!arguments[offset + 2].isUndefined()) {
      //        CHECK(args[*offset + 2]->IsInt32());
      config.saltlen = static_cast<int>(arguments[offset + 2].asNumber());

      if (config.saltlen < 0) {
        throw jsi::JSError(runtime, "salt length is out of range");
      }
    }

    offset += 3;
  }

  config.public_key_encoding = ManagedEVPPKey::GetPublicKeyEncodingFromJs(
      runtime, arguments, &offset, kKeyContextGenerate);

  auto private_key_encoding = ManagedEVPPKey::GetPrivateKeyEncodingFromJs(
      runtime, arguments, &offset, kKeyContextGenerate);

  if (!private_key_encoding.IsEmpty()) {
    config.private_key_encoding = private_key_encoding.Release();
  }

  return config;
}

std::pair<jsi::Value, jsi::Value> generateRsaKeyPair(
    jsi::Runtime& runtime, std::shared_ptr<RsaKeyPairGenConfig> config) {
  // TODO: this is all copied into crypto_ec.cpp - template it up like Node?
  CheckEntropy();

  EVPKeyCtxPointer ctx = setup(config);

  if (!ctx) {
    throw jsi::JSError(runtime, "Error on key generation job");
  }

  // Generate the key
  EVP_PKEY* pkey = nullptr;
  if (!EVP_PKEY_keygen(ctx.get(), &pkey)) {
    throw jsi::JSError(runtime, "Error generating key");
  }

  config->key = ManagedEVPPKey(EVPKeyPointer(pkey));

  jsi::Value publicBuffer =
      ManagedEVPPKey::ToEncodedPublicKey(runtime, std::move(config->key),
                                         config->public_key_encoding);
  jsi::Value privateBuffer =
      ManagedEVPPKey::ToEncodedPrivateKey(runtime, std::move(config->key),
                                          config->private_key_encoding);

  if (publicBuffer.isUndefined() || privateBuffer.isUndefined()) {
    throw jsi::JSError(runtime, "Failed to encode public and/or private key (RSA)");
  }

  return {std::move(publicBuffer), std::move(privateBuffer)};
}

jsi::Value ExportJWKRsaKey(jsi::Runtime &rt,
                           std::shared_ptr<KeyObjectData> key,
                           jsi::Object &target) {
  ManagedEVPPKey m_pkey = key->GetAsymmetricKey();
  // std::scoped_lock lock(*m_pkey.mutex()); // TODO: mutex/lock required?
  int type = EVP_PKEY_id(m_pkey.get());
  CHECK(type == EVP_PKEY_RSA || type == EVP_PKEY_RSA_PSS);

  // TODO(tniessen): Remove the "else" branch once we drop support for OpenSSL
  // versions older than 1.1.1e via FIPS / dynamic linking.
  const RSA* rsa;
  if (OpenSSL_version_num() >= 0x1010105fL) {
    rsa = EVP_PKEY_get0_RSA(m_pkey.get());
  } else {
    rsa = static_cast<const RSA*>(EVP_PKEY_get0(m_pkey.get()));
  }
  CHECK_NOT_NULL(rsa);

  const BIGNUM* n;
  const BIGNUM* e;
  const BIGNUM* d;
  const BIGNUM* p;
  const BIGNUM* q;
  const BIGNUM* dp;
  const BIGNUM* dq;
  const BIGNUM* qi;
  RSA_get0_key(rsa, &n, &e, &d);

  target.setProperty(rt, "kty", "RSA");
  target.setProperty(rt, "n", EncodeBignum(n, 0, true));
  target.setProperty(rt, "e", EncodeBignum(e, 0, true));

  if (key->GetKeyType() == kKeyTypePrivate) {
    RSA_get0_factors(rsa, &p, &q);
    RSA_get0_crt_params(rsa, &dp, &dq, &qi);
    target.setProperty(rt, "d", EncodeBignum(d, 0, true));
    target.setProperty(rt, "p", EncodeBignum(p, 0, true));
    target.setProperty(rt, "q", EncodeBignum(q, 0, true));
    target.setProperty(rt, "dp", EncodeBignum(dp, 0, true));
    target.setProperty(rt, "dq", EncodeBignum(dq, 0, true));
    target.setProperty(rt, "qi", EncodeBignum(qi, 0, true));
  }

  return std::move(target);
}

std::shared_ptr<KeyObjectData> ImportJWKRsaKey(jsi::Runtime &rt,
                                               jsi::Object &jwk) {
  jsi::Value n_value = jwk.getProperty(rt, "n");
  jsi::Value e_value = jwk.getProperty(rt, "e");
  jsi::Value d_value = jwk.getProperty(rt, "d");

  if (!n_value.isString() ||
      !e_value.isString()) {
    throw jsi::JSError(rt, "Invalid JWK RSA key");
    return std::shared_ptr<KeyObjectData>();
  }

  if (!d_value.isUndefined() && !d_value.isString()) {
    throw jsi::JSError(rt, "Invalid JWK RSA key");
    return std::shared_ptr<KeyObjectData>();
  }

  KeyType type = d_value.isString() ? kKeyTypePrivate : kKeyTypePublic;

  RsaPointer rsa(RSA_new());

  ByteSource n = ByteSource::FromEncodedString(rt, n_value.asString(rt).utf8(rt));
  ByteSource e = ByteSource::FromEncodedString(rt, e_value.asString(rt).utf8(rt));

  if (!RSA_set0_key(
          rsa.get(),
          n.ToBN().release(),
          e.ToBN().release(),
          nullptr)) {
    throw jsi::JSError(rt, "Invalid JWK RSA key");
    return std::shared_ptr<KeyObjectData>();
  }

  if (type == kKeyTypePrivate) {
    jsi::Value p_value = jwk.getProperty(rt, "p");
    jsi::Value q_value = jwk.getProperty(rt, "q");
    jsi::Value dp_value = jwk.getProperty(rt, "dp");
    jsi::Value dq_value = jwk.getProperty(rt, "dq");
    jsi::Value qi_value = jwk.getProperty(rt, "qi");

    if (!p_value.isString() ||
        !q_value.isString() ||
        !dp_value.isString() ||
        !dq_value.isString() ||
        !qi_value.isString()) {
      throw jsi::JSError(rt, "Invalid JWK RSA key");
      return std::shared_ptr<KeyObjectData>();
    }

    ByteSource d = ByteSource::FromEncodedString(rt, d_value.asString(rt).utf8(rt));
    ByteSource q = ByteSource::FromEncodedString(rt, q_value.asString(rt).utf8(rt));
    ByteSource p = ByteSource::FromEncodedString(rt, p_value.asString(rt).utf8(rt));
    ByteSource dp = ByteSource::FromEncodedString(rt, dp_value.asString(rt).utf8(rt));
    ByteSource dq = ByteSource::FromEncodedString(rt, dq_value.asString(rt).utf8(rt));
    ByteSource qi = ByteSource::FromEncodedString(rt, qi_value.asString(rt).utf8(rt));

    if (!RSA_set0_key(rsa.get(), nullptr, nullptr, d.ToBN().release()) ||
        !RSA_set0_factors(rsa.get(), p.ToBN().release(), q.ToBN().release()) ||
        !RSA_set0_crt_params(
            rsa.get(),
            dp.ToBN().release(),
            dq.ToBN().release(),
            qi.ToBN().release())) {
      throw jsi::JSError(rt, "Invalid JWK RSA key");
      return std::shared_ptr<KeyObjectData>();
    }
  }

  EVPKeyPointer pkey(EVP_PKEY_new());
  CHECK_EQ(EVP_PKEY_set1_RSA(pkey.get(), rsa.get()), 1);

  return KeyObjectData::CreateAsymmetric(type, ManagedEVPPKey(std::move(pkey)));
}

jsi::Value GetRsaKeyDetail(jsi::Runtime &rt,
                           std::shared_ptr<KeyObjectData> key) {
  jsi::Object target = jsi::Object(rt);
  const BIGNUM* e;  // Public Exponent
  const BIGNUM* n;  // Modulus

  ManagedEVPPKey m_pkey = key->GetAsymmetricKey();
  // std::scoped_lock lock(*m_pkey.mutex()); // TODO: mutex/lock required?
  int type = EVP_PKEY_id(m_pkey.get());
  CHECK(type == EVP_PKEY_RSA || type == EVP_PKEY_RSA_PSS);

  // TODO(tniessen): Remove the "else" branch once we drop support for OpenSSL
  // versions older than 1.1.1e via FIPS / dynamic linking.
  const RSA* rsa;
  if (OpenSSL_version_num() >= 0x1010105fL) {
    rsa = EVP_PKEY_get0_RSA(m_pkey.get());
  } else {
    rsa = static_cast<const RSA*>(EVP_PKEY_get0(m_pkey.get()));
  }
  CHECK_NOT_NULL(rsa);

  RSA_get0_key(rsa, &n, &e, nullptr);

  size_t modulus_length = BN_num_bits(n);
  // TODO: should this be modulusLength or n?
  target.setProperty(rt, "modulusLength", static_cast<double>(modulus_length));

  size_t exp_size = BN_num_bytes(e);
  // TODO: should this be publicExponent or e?
  target.setProperty(rt, "publicExponent", EncodeBignum(e, exp_size, true));

  if (type == EVP_PKEY_RSA_PSS) {
    // Due to the way ASN.1 encoding works, default values are omitted when
    // encoding the data structure. However, there are also RSA-PSS keys for
    // which no parameters are set. In that case, the ASN.1 RSASSA-PSS-params
    // sequence will be missing entirely and RSA_get0_pss_params will return
    // nullptr. If parameters are present but all parameters are set to their
    // default values, an empty sequence will be stored in the ASN.1 structure.
    // In that case, RSA_get0_pss_params does not return nullptr but all fields
    // of the returned RSA_PSS_PARAMS will be set to nullptr.

    const RSA_PSS_PARAMS* params = RSA_get0_pss_params(rsa);
    if (params != nullptr) {
      int hash_nid = NID_sha1;
      int mgf_nid = NID_mgf1;
      int mgf1_hash_nid = NID_sha1;
      int64_t salt_length = 20;

      if (params->hashAlgorithm != nullptr) {
        const ASN1_OBJECT* hash_obj;
        X509_ALGOR_get0(&hash_obj, nullptr, nullptr, params->hashAlgorithm);
        hash_nid = OBJ_obj2nid(hash_obj);
      }

      target.setProperty(rt, "hashAlgorithm", std::string(OBJ_nid2ln(hash_nid)));

      if (params->maskGenAlgorithm != nullptr) {
        const ASN1_OBJECT* mgf_obj;
        X509_ALGOR_get0(&mgf_obj, nullptr, nullptr, params->maskGenAlgorithm);
        mgf_nid = OBJ_obj2nid(mgf_obj);
        if (mgf_nid == NID_mgf1) {
          const ASN1_OBJECT* mgf1_hash_obj;
          X509_ALGOR_get0(&mgf1_hash_obj, nullptr, nullptr, params->maskHash);
          mgf1_hash_nid = OBJ_obj2nid(mgf1_hash_obj);
        }
      }

      // If, for some reason, the MGF is not MGF1, then the MGF1 hash function
      // is intentionally not added to the object.
      if (mgf_nid == NID_mgf1) {
        target.setProperty(rt, "mgf1HashAlgorithm", std::string(OBJ_nid2ln(mgf1_hash_nid)));
      }

      if (params->saltLength != nullptr) {
        if (ASN1_INTEGER_get_int64(&salt_length, params->saltLength) != 1) {
          throw jsi::JSError(rt, "ASN1_INTEGER_get_in64 error: " +
            std::to_string(ERR_get_error()));
          return target;
        }
      }

      target.setProperty(rt, "saltLength", static_cast<double>(salt_length));
    }
  }

  return target;
}

}  // namespace margelo
