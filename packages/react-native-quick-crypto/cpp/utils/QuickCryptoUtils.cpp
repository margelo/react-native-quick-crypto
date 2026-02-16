#include "QuickCryptoUtils.hpp"
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <stdexcept>

namespace margelo::nitro::crypto {

EVP_PKEY* createEcEvpPkey(const char* group_name, const uint8_t* pub_oct, size_t pub_len, const BIGNUM* priv_bn) {
  OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
  if (!bld)
    throw std::runtime_error("Failed to create OSSL_PARAM_BLD");

  OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, group_name, 0);
  OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pub_oct, pub_len);
  if (priv_bn)
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, priv_bn);

  OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
  OSSL_PARAM_BLD_free(bld);
  if (!params)
    throw std::runtime_error("Failed to build EC parameters");

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
  if (!ctx) {
    OSSL_PARAM_free(params);
    throw std::runtime_error("Failed to create EVP_PKEY_CTX for EC");
  }

  int selection = priv_bn ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY;
  EVP_PKEY* pkey = nullptr;
  if (EVP_PKEY_fromdata_init(ctx) <= 0 || EVP_PKEY_fromdata(ctx, &pkey, selection, params) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    throw std::runtime_error("Failed to create EVP_PKEY from EC parameters");
  }

  EVP_PKEY_CTX_free(ctx);
  OSSL_PARAM_free(params);
  return pkey;
}

} // namespace margelo::nitro::crypto
