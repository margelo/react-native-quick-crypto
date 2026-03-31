#include "QuickCryptoUtils.hpp"
#include <iomanip>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <sstream>
#include <stdexcept>
#include <string>

namespace margelo::nitro::crypto {

static std::string getOpenSslErrors() {
  std::ostringstream oss;
  bool first = true;
  unsigned long errCode = ERR_get_error();
  while (errCode != 0) {
    char buf[256];
    ERR_error_string_n(errCode, buf, sizeof(buf));
    if (!first)
      oss << " | ";
    oss << buf;
    first = false;
    errCode = ERR_get_error();
  }
  return first ? "none" : oss.str();
}

static std::string toHexByte(uint8_t b) {
  std::ostringstream oss;
  oss << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
  return oss.str();
}

EVP_PKEY* createEcEvpPkey(const char* group_name, const uint8_t* pub_oct, size_t pub_len, const BIGNUM* priv_bn) {
  // Clear stale OpenSSL errors before entering this routine.
  ERR_clear_error();

  int nid = OBJ_txt2nid(group_name);
  bool pointDecodeOk = false;
  if (nid != NID_undef && pub_oct != nullptr && pub_len > 0) {
    EC_GROUP* group = EC_GROUP_new_by_curve_name(nid);
    if (group != nullptr) {
      EC_POINT* point = EC_POINT_new(group);
      if (point != nullptr) {
        pointDecodeOk = (EC_POINT_oct2point(group, point, pub_oct, pub_len, nullptr) == 1);
        EC_POINT_free(point);
      }
      EC_GROUP_free(group);
    }
  }

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
    std::string errors = getOpenSslErrors();
    std::ostringstream message;
    message << "Failed to create EVP_PKEY from EC parameters"
            << " (group=" << (group_name ? group_name : "null") << ", pub_len=" << pub_len
            << ", pub_first=" << ((pub_oct != nullptr && pub_len > 0) ? toHexByte(pub_oct[0]) : "n/a")
            << ", point_decode_ok=" << (pointDecodeOk ? "true" : "false") << ", openssl_errors=" << errors << ")";
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    throw std::runtime_error(message.str());
  }

  EVP_PKEY_CTX_free(ctx);
  OSSL_PARAM_free(params);
  return pkey;
}

} // namespace margelo::nitro::crypto
