//
//  crypto_ec.cpp
//  BEMCheckBox
//
//  Created by Oscar Franco on 30/11/23.
//

#include "crypto_ec.h"
#include <iostream>
#include <openssl/ec.h>
#include <string>
#include <utility>

namespace margelo {
namespace jsi = facebook::jsi;

int GetCurveFromName(const char* name) {
  int nid = EC_curve_nist2nid(name);
  if (nid == NID_undef)
    nid = OBJ_sn2nid(name);
  return nid;
}

ECPointPointer ECDH::BufferToPoint(jsi::Runtime &rt,
                                   const EC_GROUP* group,
                                   jsi::ArrayBuffer &buf) {
    int r;

    ECPointPointer pub(EC_POINT_new(group));
    if (!pub) {
        throw std::runtime_error(
            "Failed to allocate EC_POINT for a public key");
        return pub;
    }

    // TODO(osp) re-insert this check
    //  if (UNLIKELY(!input.CheckSizeInt32())) {
    //    THROW_ERR_OUT_OF_RANGE(env, "buffer is too big");
    //    return ECPointPointer();
    //  }
    r = EC_POINT_oct2point(
                           group,
                           pub.get(),
                           buf.data(rt),
                           buf.size(rt),
                           nullptr);

    if (!r) {
      return ECPointPointer();
    }
    return pub;
}

WebCryptoKeyExportStatus ECDH::doExport(jsi::Runtime &rt,
                                        std::shared_ptr<KeyObjectData> key_data,
                                        WebCryptoKeyFormat format,
                                        const ECKeyExportConfig& params,
                                        ByteSource* out) {
    CHECK_NE(key_data->GetKeyType(), kKeyTypeSecret);

    switch (format) {
        case kWebCryptoKeyFormatRaw:
            return EC_Raw_Export(key_data.get(), params, out);
        // case kWebCryptoKeyFormatPKCS8:
        //     if (key_data->GetKeyType() != kKeyTypePrivate)
        //         return WebCryptoKeyExportStatus::INVALID_KEY_TYPE;
        //     return PKEY_PKCS8_Export(key_data.get(), out);
        case kWebCryptoKeyFormatSPKI: {
            if (key_data->GetKeyType() != kKeyTypePublic)
                throw std::runtime_error("Invalid type public to be exported");

            ManagedEVPPKey m_pkey = key_data->GetAsymmetricKey();
            if (EVP_PKEY_id(m_pkey.get()) != EVP_PKEY_EC) {
                return PKEY_SPKI_Export(key_data.get(), out);
            } else {
                // Ensure exported key is in uncompressed point format.
                // The temporary EC key is so we can have i2d_PUBKEY_bio() write out
                // the header but it is a somewhat silly hoop to jump through because
                // the header is for all practical purposes a static 26 byte sequence
                // where only the second byte changes.

                const EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(m_pkey.get());
                const EC_GROUP* group = EC_KEY_get0_group(ec_key);
                const EC_POINT* point = EC_KEY_get0_public_key(ec_key);
                const point_conversion_form_t form =
                    POINT_CONVERSION_UNCOMPRESSED;
                const size_t need =
                    EC_POINT_point2oct(group, point, form, nullptr, 0, nullptr);
                if (need == 0) {
                    throw std::runtime_error("Failed to export EC key");
                }
                ByteSource::Builder data(need);
                const size_t have = EC_POINT_point2oct(group,
                        point, form, data.data<unsigned char>(), need, nullptr);
                if (have == 0) {
                    throw std::runtime_error("Failed to export EC key");
                }
                ECKeyPointer ec(EC_KEY_new());
                CHECK_EQ(1, EC_KEY_set_group(ec.get(), group));
                ECPointPointer uncompressed(EC_POINT_new(group));
                CHECK_EQ(1,
                         EC_POINT_oct2point(group,
                                            uncompressed.get(),
                                            data.data<unsigned char>(),
                                            data.size(),
                                            nullptr));
                CHECK_EQ(1, EC_KEY_set_public_key(ec.get(),
                                                    uncompressed.get()));
                EVPKeyPointer pkey(EVP_PKEY_new());
                CHECK_EQ(1, EVP_PKEY_set1_EC_KEY(pkey.get(), ec.get()));
                BIOPointer bio(BIO_new(BIO_s_mem()));
                CHECK(bio);
                if (!i2d_PUBKEY_bio(bio.get(), pkey.get())) {
                    throw std::runtime_error("Failed to export EC key");
                }
                *out = ByteSource::FromBIO(bio);
                return WebCryptoKeyExportStatus::OK;
            }
        }
        default:
            throw std::runtime_error("Un-reachable export code");
    }
}

WebCryptoKeyExportStatus PKEY_SPKI_Export(KeyObjectData* key_data,
                                          ByteSource* out) {
    CHECK_EQ(key_data->GetKeyType(), kKeyTypePublic);
    ManagedEVPPKey m_pkey = key_data->GetAsymmetricKey();
    // Mutex::ScopedLock lock(*m_pkey.mutex());
    BIOPointer bio(BIO_new(BIO_s_mem()));
    CHECK(bio);
    if (!i2d_PUBKEY_bio(bio.get(), m_pkey.get())) {
        throw std::runtime_error("Failed to export key");
        return WebCryptoKeyExportStatus::FAILED;
    }

    *out = ByteSource::FromBIO(bio);
    return WebCryptoKeyExportStatus::OK;
}

WebCryptoKeyExportStatus EC_Raw_Export(KeyObjectData* key_data,
                                       const ECKeyExportConfig& params,
                                       ByteSource* out) {
  ManagedEVPPKey m_pkey = key_data->GetAsymmetricKey();
  CHECK(m_pkey);
  // std::scoped_lock lock(*m_pkey.mutex()); // TODO: mutex/lock required?

  const EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(m_pkey.get());

  size_t len = 0;

  if (ec_key == nullptr) {
    typedef int (*export_fn)(const EVP_PKEY*, unsigned char*, size_t* len);
    export_fn fn = nullptr;
    switch (key_data->GetKeyType()) {
      case kKeyTypePrivate:
        fn = EVP_PKEY_get_raw_private_key;
        break;
      case kKeyTypePublic:
        fn = EVP_PKEY_get_raw_public_key;
        break;
      case kKeyTypeSecret:
        throw std::runtime_error("unreachable code in EC_Raw_Export");
    }
    CHECK_NOT_NULL(fn);
    // Get the size of the raw key data
    if (fn(m_pkey.get(), nullptr, &len) == 0)
      return WebCryptoKeyExportStatus::INVALID_KEY_TYPE;
    ByteSource::Builder data(len);
    if (fn(m_pkey.get(), data.data<unsigned char>(), &len) == 0)
      return WebCryptoKeyExportStatus::INVALID_KEY_TYPE;
    *out = std::move(data).release(len);
  } else {
    if (key_data->GetKeyType() != kKeyTypePublic)
      return WebCryptoKeyExportStatus::INVALID_KEY_TYPE;
    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    const EC_POINT* point = EC_KEY_get0_public_key(ec_key);
    point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;

    // Get the allocated data size...
    len = EC_POINT_point2oct(group, point, form, nullptr, 0, nullptr);
    if (len == 0)
      return WebCryptoKeyExportStatus::FAILED;
    ByteSource::Builder data(len);
    size_t check_len = EC_POINT_point2oct(
        group, point, form, data.data<unsigned char>(), len, nullptr);
    if (check_len == 0)
      return WebCryptoKeyExportStatus::FAILED;

    CHECK_EQ(len, check_len);
    *out = std::move(data).release();
  }

  return WebCryptoKeyExportStatus::OK;
}

jsi::Value ExportJWKEcKey(jsi::Runtime &rt,
                          std::shared_ptr<KeyObjectData> key,
                          jsi::Object &target) {
  ManagedEVPPKey m_pkey = key->GetAsymmetricKey();
  // std::scoped_lock lock(*m_pkey.mutex()); // TODO: mutex/lock required?
  CHECK_EQ(EVP_PKEY_id(m_pkey.get()), EVP_PKEY_EC);

  const EC_KEY* ec = EVP_PKEY_get0_EC_KEY(m_pkey.get());
  CHECK_NOT_NULL(ec);

  const EC_POINT* pub = EC_KEY_get0_public_key(ec);
  const EC_GROUP* group = EC_KEY_get0_group(ec);

  int degree_bits = EC_GROUP_get_degree(group);
  int degree_bytes =
    (degree_bits / CHAR_BIT) + (7 + (degree_bits % CHAR_BIT)) / 8;

  BignumPointer x(BN_new());
  BignumPointer y(BN_new());

  if (!EC_POINT_get_affine_coordinates(group, pub, x.get(), y.get(), nullptr)) {
    throw jsi::JSError(rt, "Failed to get elliptic-curve point coordinates");
  }

  target.setProperty(rt, "kty", "EC");
  target.setProperty(rt, "x", EncodeBignum(x.get(), degree_bytes, true));
  target.setProperty(rt, "y", EncodeBignum(y.get(), degree_bytes, true));

  std::string crv_name;
  const int nid = EC_GROUP_get_curve_name(group);
  switch (nid) {
    case NID_X9_62_prime256v1:
      crv_name = "P-256";
      break;
    case NID_secp256k1:
      crv_name = "secp256k1";
      break;
    case NID_secp384r1:
      crv_name = "P-384";
      break;
    case NID_secp521r1:
      crv_name = "P-521";
      break;
    default: {
      throw jsi::JSError(rt, "Unsupported JWK EC curve: %s.", OBJ_nid2sn(nid));
      return jsi::Value::undefined();
    }
  }
  target.setProperty(rt, "crv", crv_name);

  if (key->GetKeyType() == kKeyTypePrivate) {
    const BIGNUM* pvt = EC_KEY_get0_private_key(ec);
    target.setProperty(rt, "d", EncodeBignum(pvt, degree_bytes, true));
  }

  return std::move(target);
}

std::shared_ptr<KeyObjectData> ImportJWKEcKey(jsi::Runtime &rt,
                                              jsi::Object &jwk,
                                              jsi::Value &namedCurve) {
  // curve name
  if (namedCurve.isUndefined()) {
    throw jsi::JSError(rt, "Invalid Named Curve");
    return std::shared_ptr<KeyObjectData>();
  }
  std::string curve = namedCurve.asString(rt).utf8(rt);

  int nid = GetCurveFromName(curve.c_str());
  if (nid == NID_undef) {  // Unknown curve
    throw jsi::JSError(rt, "Invalid Named Curve: " + curve);
    return std::shared_ptr<KeyObjectData>();
  }

  jsi::Value x_value = jwk.getProperty(rt, "x");
  jsi::Value y_value = jwk.getProperty(rt, "y");
  jsi::Value d_value = jwk.getProperty(rt, "d");

  if (!x_value.isString() ||
      !y_value.isString() ||
      (!d_value.isUndefined() && !d_value.isString())) {
    throw jsi::JSError(rt, "Invalid JWK EC key 0");
  }

  KeyType type = d_value.isString() ? kKeyTypePrivate : kKeyTypePublic;

  ECKeyPointer ec(EC_KEY_new_by_curve_name(nid));
  if (!ec) {
    throw jsi::JSError(rt, "Invalid JWK EC key 1");
  }

  ByteSource x = ByteSource::FromEncodedString(rt,
                                               x_value.asString(rt).utf8(rt),
                                               encoding::BASE64URL);
  ByteSource y = ByteSource::FromEncodedString(rt,
                                               y_value.asString(rt).utf8(rt),
                                               encoding::BASE64URL);

  int r = EC_KEY_set_public_key_affine_coordinates(ec.get(),
                                                  x.ToBN().get(),
                                                  y.ToBN().get());
  if (!r) {
    throw jsi::JSError(rt, "Invalid JWK EC key 2");
  }

  if (type == kKeyTypePrivate) {
    ByteSource d = ByteSource::FromEncodedString(rt, d_value.asString(rt).utf8(rt));
    if (!EC_KEY_set_private_key(ec.get(), d.ToBN().get())) {
      throw jsi::JSError(rt, "Invalid JWK EC key 3");
      return std::shared_ptr<KeyObjectData>();
    }
  }

  EVPKeyPointer pkey(EVP_PKEY_new());
  CHECK_EQ(EVP_PKEY_set1_EC_KEY(pkey.get(), ec.get()), 1);

  return KeyObjectData::CreateAsymmetric(type, ManagedEVPPKey(std::move(pkey)));
}

jsi::Value GetEcKeyDetail(jsi::Runtime &rt,
                          std::shared_ptr<KeyObjectData> key) {
  jsi::Object target = jsi::Object(rt);
  ManagedEVPPKey m_pkey = key->GetAsymmetricKey();
  // std::scoped_lock lock(*m_pkey.mutex()); // TODO: mutex/lock required?
  CHECK_EQ(EVP_PKEY_id(m_pkey.get()), EVP_PKEY_EC);

  const EC_KEY* ec = EVP_PKEY_get0_EC_KEY(m_pkey.get());
  CHECK_NOT_NULL(ec);

  const EC_GROUP* group = EC_KEY_get0_group(ec);
  int nid = EC_GROUP_get_curve_name(group);

  jsi::String value = jsi::String::createFromUtf8(rt, OBJ_nid2sn(nid));
  target.setProperty(rt, "namedCurve", value);
  return target;
}

EcKeyPairGenConfig prepareEcKeyGenConfig(jsi::Runtime &rt,
                                       const jsi::Value *args)
{
  EcKeyPairGenConfig config = EcKeyPairGenConfig();

  // curve name
  std::string curveName = args[1].asString(rt).utf8(rt);
  config.curve_nid = GetCurveFromName(curveName.c_str());

  // encoding
  if (CheckIsInt32(args[2].asNumber())) {
    int encoding = static_cast<int>(args[2].asNumber());
    if (encoding != OPENSSL_EC_NAMED_CURVE &&
        encoding != OPENSSL_EC_EXPLICIT_CURVE) {
      throw jsi::JSError(rt, "Invalid param_encoding specified");
    } else {
      config.param_encoding = encoding;
    }
  } else {
    throw jsi::JSError(rt, "Invalid param_encoding specified (not int)");
  }

  // rest of args for encoding
  unsigned int offset = 3;

  config.public_key_encoding = ManagedEVPPKey::GetPublicKeyEncodingFromJs(
      rt, args, &offset, kKeyContextGenerate);

  auto private_key_encoding = ManagedEVPPKey::GetPrivateKeyEncodingFromJs(
      rt, args, &offset, kKeyContextGenerate);

  if (!private_key_encoding.IsEmpty()) {
    config.private_key_encoding = private_key_encoding.Release();
  }

  return config;
}

EVPKeyCtxPointer setup(std::shared_ptr<EcKeyPairGenConfig> config) {
  EVPKeyCtxPointer key_ctx;
  switch (config->curve_nid) {
    case EVP_PKEY_ED25519:
      // Fall through
    case EVP_PKEY_ED448:
      // Fall through
    case EVP_PKEY_X25519:
      // Fall through
    case EVP_PKEY_X448:
      key_ctx.reset(EVP_PKEY_CTX_new_id(config->curve_nid, nullptr));
      break;
    default: {
      EVPKeyCtxPointer param_ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
      EVP_PKEY* raw_params = nullptr;
      if (!param_ctx ||
          EVP_PKEY_paramgen_init(param_ctx.get()) <= 0 ||
          EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
              param_ctx.get(), config->curve_nid) <= 0 ||
          EVP_PKEY_CTX_set_ec_param_enc(
              param_ctx.get(), config->param_encoding) <= 0 ||
          EVP_PKEY_paramgen(param_ctx.get(), &raw_params) <= 0) {
        return EVPKeyCtxPointer();
      }
      EVPKeyPointer key_params(raw_params);
      key_ctx.reset(EVP_PKEY_CTX_new(key_params.get(), nullptr));
    }
  }

  if (key_ctx && EVP_PKEY_keygen_init(key_ctx.get()) <= 0)
    key_ctx.reset();

  return key_ctx;
}

std::pair<jsi::Value, jsi::Value> generateEcKeyPair(jsi::Runtime& runtime,
                                                    std::shared_ptr<EcKeyPairGenConfig> config)
{
  // TODO: this is all copied from MGLRsa.cpp - template it up like Node?

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
    throw jsi::JSError(runtime, "Failed to encode public and/or private key (EC)");
  }

  return {std::move(publicBuffer), std::move(privateBuffer)};
}

} // namespace margelo
