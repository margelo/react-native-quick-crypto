//
//  crypto_ec.cpp
//  BEMCheckBox
//
//  Created by Oscar Franco on 30/11/23.
//

#include "crypto_ec.h"
#include <openssl/ec.h>

namespace margelo {
namespace jsi = facebook::jsi;

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

    if (!r)
        return ECPointPointer();

    return pub;
}

void PKEY_SPKI_Export(
                      KeyObjectData* key_data,
                      ByteSource* out) {
    CHECK_EQ(key_data->GetKeyType(), kKeyTypePublic);
    ManagedEVPPKey m_pkey = key_data->GetAsymmetricKey();
    //                    Mutex::ScopedLock lock(*m_pkey.mutex());
    BIOPointer bio(BIO_new(BIO_s_mem()));
    CHECK(bio);
    if (!i2d_PUBKEY_bio(bio.get(), m_pkey.get()))
        throw std::runtime_error("Failed to export key");

    *out = ByteSource::FromBIO(bio);
}

void ECDH::doExport(jsi::Runtime &rt,
                    WebCryptoKeyFormat format,
                    std::shared_ptr<KeyObjectData> key_data,
                    ByteSource* out) {
    //    CHECK_NE(key_data->GetKeyType(), kKeyTypeSecret);

    switch (format) {
            //        case kWebCryptoKeyFormatRaw:
            //            return EC_Raw_Export(key_data.get(), params, out);
            //        case kWebCryptoKeyFormatPKCS8:
            //            if (key_data->GetKeyType() != kKeyTypePrivate)
            //                return WebCryptoKeyExportStatus::INVALID_KEY_TYPE;
            //            return PKEY_PKCS8_Export(key_data.get(), out);
        case kWebCryptoKeyFormatSPKI: {
            if (key_data->GetKeyType() != kKeyTypePublic)
                throw std::runtime_error("Invalid type public to be exported");

            ManagedEVPPKey m_pkey = key_data->GetAsymmetricKey();
            if (EVP_PKEY_id(m_pkey.get()) != EVP_PKEY_EC) {
                PKEY_SPKI_Export(key_data.get(), out);
                return;
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
                return;
            }
        }
        default:
            throw std::runtime_error("Un-reachable export code");;
    }
}

} // namespace margelo
