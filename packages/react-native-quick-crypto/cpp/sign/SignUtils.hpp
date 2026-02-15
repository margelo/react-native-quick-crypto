#pragma once

#include <cstring>
#include <memory>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <string>

#include "../utils/QuickCryptoUtils.hpp"

namespace margelo::nitro::crypto {

enum DSASigEnc {
  kSigEncDER = 0,
  kSigEncP1363 = 1,
};

inline unsigned int getBytesOfRS(EVP_PKEY* pkey) {
  int bits;
  int base_id = EVP_PKEY_base_id(pkey);

  if (base_id == EVP_PKEY_DSA) {
    const DSA* dsa_key = EVP_PKEY_get0_DSA(pkey);
    bits = BN_num_bits(DSA_get0_q(dsa_key));
  } else if (base_id == EVP_PKEY_EC) {
    const EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(pkey);
    const EC_GROUP* ec_group = EC_KEY_get0_group(ec_key);
    bits = EC_GROUP_order_bits(ec_group);
  } else {
    return 0;
  }

  return (bits + 7) / 8;
}

inline bool convertSignatureToP1363(const unsigned char* sig_data, size_t sig_len, unsigned char* out, size_t n) {
  ECDSA_SIG* asn1_sig = d2i_ECDSA_SIG(nullptr, &sig_data, sig_len);
  if (!asn1_sig)
    return false;

  const BIGNUM* pr = ECDSA_SIG_get0_r(asn1_sig);
  const BIGNUM* ps = ECDSA_SIG_get0_s(asn1_sig);

  bool success = BN_bn2binpad(pr, out, static_cast<int>(n)) > 0 && BN_bn2binpad(ps, out + n, static_cast<int>(n)) > 0;
  ECDSA_SIG_free(asn1_sig);
  return success;
}

inline std::unique_ptr<uint8_t[]> convertSignatureToDER(const unsigned char* sig_data, size_t sig_len, size_t n, size_t* out_len) {
  if (sig_len != 2 * n) {
    return nullptr;
  }

  ECDSA_SIG* asn1_sig = ECDSA_SIG_new();
  if (!asn1_sig)
    return nullptr;

  BIGNUM* r = BN_bin2bn(sig_data, static_cast<int>(n), nullptr);
  BIGNUM* s = BN_bin2bn(sig_data + n, static_cast<int>(n), nullptr);

  if (!r || !s || !ECDSA_SIG_set0(asn1_sig, r, s)) {
    if (r)
      BN_free(r);
    if (s)
      BN_free(s);
    ECDSA_SIG_free(asn1_sig);
    return nullptr;
  }

  int der_len = i2d_ECDSA_SIG(asn1_sig, nullptr);
  if (der_len <= 0) {
    ECDSA_SIG_free(asn1_sig);
    return nullptr;
  }

  auto der_buf = std::make_unique<uint8_t[]>(der_len);
  unsigned char* der_ptr = der_buf.get();
  i2d_ECDSA_SIG(asn1_sig, &der_ptr);

  ECDSA_SIG_free(asn1_sig);
  *out_len = der_len;
  return der_buf;
}

} // namespace margelo::nitro::crypto
