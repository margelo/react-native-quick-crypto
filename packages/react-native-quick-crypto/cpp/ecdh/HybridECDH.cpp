#include "HybridECDH.hpp"
#include "QuickCryptoUtils.hpp"
#include <NitroModules/ArrayBuffer.hpp>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <stdexcept>

namespace margelo::nitro::crypto {

// Smart pointer type aliases for RAII
using EVP_PKEY_CTX_ptr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using EC_POINT_ptr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;
using BN_ptr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;

void HybridECDH::init(const std::string& curveName) {
  int nid = getCurveNid(curveName);
  if (nid == NID_undef) {
    throw std::runtime_error("ECDH: unknown curve name: " + curveName);
  }

  EC_GROUP_ptr group(EC_GROUP_new_by_curve_name(nid), EC_GROUP_free);
  if (!group) {
    throw std::runtime_error("ECDH: failed to create EC group for curve: " + curveName);
  }

  _curveName = curveName;
  _curveNid = nid;
  _group = std::move(group);
  _pkey.reset();
}

std::shared_ptr<ArrayBuffer> HybridECDH::generateKeys() {
  ensureInitialized();

  EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free);
  if (!ctx) {
    throw std::runtime_error("ECDH: failed to create keygen context");
  }

  if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
    throw std::runtime_error("ECDH: failed to initialize key generation");
  }

  if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), _curveNid) <= 0) {
    throw std::runtime_error("ECDH: failed to set curve");
  }

  EVP_PKEY* pkey = nullptr;
  if (EVP_PKEY_keygen(ctx.get(), &pkey) <= 0) {
    throw std::runtime_error("ECDH: failed to generate key pair");
  }

  _pkey.reset(pkey);

  return getPublicKey();
}

std::shared_ptr<ArrayBuffer> HybridECDH::computeSecret(const std::shared_ptr<ArrayBuffer>& otherPublicKey) {
  ensureInitialized();
  if (!_pkey) {
    throw std::runtime_error("ECDH: private key not set");
  }

  // Build peer EVP_PKEY from raw public key octets
  EVP_PKEY_ptr peerPkey(createEcEvpPkey(_curveName.c_str(), otherPublicKey->data(), otherPublicKey->size()), EVP_PKEY_free);

  // Derive shared secret using EVP API
  EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new(_pkey.get(), nullptr), EVP_PKEY_CTX_free);
  if (!ctx) {
    throw std::runtime_error("ECDH: failed to create derive context");
  }

  if (EVP_PKEY_derive_init(ctx.get()) <= 0) {
    throw std::runtime_error("ECDH: failed to initialize key derivation");
  }

  if (EVP_PKEY_derive_set_peer(ctx.get(), peerPkey.get()) <= 0) {
    throw std::runtime_error("ECDH: failed to set peer key for derivation");
  }

  // Get required buffer size
  size_t secretLen = 0;
  if (EVP_PKEY_derive(ctx.get(), nullptr, &secretLen) <= 0) {
    throw std::runtime_error("ECDH: failed to get shared secret length");
  }

  // Derive the shared secret
  std::vector<uint8_t> secret(secretLen);
  if (EVP_PKEY_derive(ctx.get(), secret.data(), &secretLen) <= 0) {
    throw std::runtime_error("ECDH: failed to derive shared secret");
  }

  secret.resize(secretLen);

  return ToNativeArrayBuffer(secret);
}

std::shared_ptr<ArrayBuffer> HybridECDH::getPrivateKey() {
  if (!_pkey) {
    throw std::runtime_error("ECDH: no key set");
  }

  BIGNUM* priv = nullptr;
  if (EVP_PKEY_get_bn_param(_pkey.get(), OSSL_PKEY_PARAM_PRIV_KEY, &priv) != 1 || !priv) {
    throw std::runtime_error("ECDH: no private key available");
  }

  int len = BN_num_bytes(priv);
  std::vector<uint8_t> buf(len);
  BN_bn2bin(priv, buf.data());
  BN_free(priv);

  return ToNativeArrayBuffer(buf);
}

void HybridECDH::setPrivateKey(const std::shared_ptr<ArrayBuffer>& privateKey) {
  ensureInitialized();

  // Convert private key bytes to BIGNUM
  BN_ptr privBn(BN_bin2bn(privateKey->data(), static_cast<int>(privateKey->size()), nullptr), BN_free);
  if (!privBn) {
    throw std::runtime_error("ECDH: failed to convert private key");
  }

  EC_POINT_ptr pubPoint(EC_POINT_new(_group.get()), EC_POINT_free);
  if (!pubPoint) {
    throw std::runtime_error("ECDH: failed to create EC point");
  }

  if (EC_POINT_mul(_group.get(), pubPoint.get(), privBn.get(), nullptr, nullptr, nullptr) != 1) {
    throw std::runtime_error("ECDH: failed to compute public key from private key");
  }

  size_t pubLen = EC_POINT_point2oct(_group.get(), pubPoint.get(), POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
  if (pubLen == 0) {
    throw std::runtime_error("ECDH: failed to get public key length");
  }
  std::vector<uint8_t> pubOct(pubLen);
  if (EC_POINT_point2oct(_group.get(), pubPoint.get(), POINT_CONVERSION_UNCOMPRESSED, pubOct.data(), pubLen, nullptr) == 0) {
    throw std::runtime_error("ECDH: failed to serialize public key");
  }

  // Build EVP_PKEY via OSSL_PARAM_BLD
  _pkey.reset(createEcEvpPkey(_curveName.c_str(), pubOct.data(), pubOct.size(), privBn.get()));
}

std::shared_ptr<ArrayBuffer> HybridECDH::getPublicKey() {
  if (!_pkey) {
    throw std::runtime_error("ECDH: no key set");
  }

  size_t len = 0;
  if (EVP_PKEY_get_octet_string_param(_pkey.get(), OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &len) != 1 || len == 0) {
    throw std::runtime_error("ECDH: failed to get public key length");
  }

  std::vector<uint8_t> buf(len);
  if (EVP_PKEY_get_octet_string_param(_pkey.get(), OSSL_PKEY_PARAM_PUB_KEY, buf.data(), buf.size(), &len) != 1) {
    throw std::runtime_error("ECDH: failed to get public key");
  }

  return ToNativeArrayBuffer(buf);
}

void HybridECDH::setPublicKey(const std::shared_ptr<ArrayBuffer>& publicKey) {
  ensureInitialized();

  // Build EVP_PKEY directly from public key octets
  _pkey.reset(createEcEvpPkey(_curveName.c_str(), publicKey->data(), publicKey->size()));
}

std::shared_ptr<ArrayBuffer> HybridECDH::convertKey(const std::shared_ptr<ArrayBuffer>& key, const std::string& curve, double format) {
  int nid = getCurveNid(curve);
  if (nid == NID_undef) {
    throw std::runtime_error("ECDH: unknown curve: " + curve);
  }

  EC_GROUP_ptr group(EC_GROUP_new_by_curve_name(nid), EC_GROUP_free);
  if (!group) {
    throw std::runtime_error("ECDH: failed to create EC group for curve: " + curve);
  }

  EC_POINT_ptr point(EC_POINT_new(group.get()), EC_POINT_free);
  if (!point) {
    throw std::runtime_error("ECDH: failed to create EC point");
  }

  if (EC_POINT_oct2point(group.get(), point.get(), key->data(), key->size(), nullptr) != 1) {
    throw std::runtime_error("ECDH: failed to decode public key");
  }

  auto form = static_cast<point_conversion_form_t>(static_cast<int>(format));

  size_t len = EC_POINT_point2oct(group.get(), point.get(), form, nullptr, 0, nullptr);
  if (len == 0) {
    throw std::runtime_error("ECDH: failed to get converted key length");
  }

  std::vector<uint8_t> buf(len);
  if (EC_POINT_point2oct(group.get(), point.get(), form, buf.data(), len, nullptr) == 0) {
    throw std::runtime_error("ECDH: failed to convert key");
  }

  return ToNativeArrayBuffer(buf);
}

void HybridECDH::ensureInitialized() const {
  if (_curveNid == 0 || !_group) {
    throw std::runtime_error("ECDH: not initialized");
  }
}

int HybridECDH::getCurveNid(const std::string& name) {
  int nid = OBJ_txt2nid(name.c_str());
  if (nid == NID_undef) {
    nid = OBJ_sn2nid(name.c_str());
  }
  if (nid == NID_undef) {
    nid = OBJ_ln2nid(name.c_str());
  }
  return nid;
}

} // namespace margelo::nitro::crypto
