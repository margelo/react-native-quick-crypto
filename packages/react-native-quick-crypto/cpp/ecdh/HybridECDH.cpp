#include "HybridECDH.hpp"
#include "QuickCryptoUtils.hpp"
#include <NitroModules/ArrayBuffer.hpp>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <stdexcept>

namespace margelo::nitro::crypto {

// Smart pointer type aliases for RAII
using EVP_PKEY_CTX_ptr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using EC_KEY_ptr = std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)>;
using EC_POINT_ptr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;
using BN_ptr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;

// Suppress deprecation warnings for EC_KEY_* functions
// These APIs work but are deprecated in OpenSSL 3.x
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

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

  // Create EC_POINT from the peer's public key bytes
  EC_POINT_ptr point(EC_POINT_new(_group.get()), EC_POINT_free);
  if (!point) {
    throw std::runtime_error("ECDH: failed to create EC point");
  }

  if (EC_POINT_oct2point(_group.get(), point.get(), otherPublicKey->data(), otherPublicKey->size(), nullptr) != 1) {
    throw std::runtime_error("ECDH: failed to decode peer public key");
  }

  // Create EC_KEY for the peer
  EC_KEY_ptr ecKey(EC_KEY_new(), EC_KEY_free);
  if (!ecKey) {
    throw std::runtime_error("ECDH: failed to create EC_KEY");
  }

  if (EC_KEY_set_group(ecKey.get(), _group.get()) != 1) {
    throw std::runtime_error("ECDH: failed to set EC group");
  }

  if (EC_KEY_set_public_key(ecKey.get(), point.get()) != 1) {
    throw std::runtime_error("ECDH: failed to set peer public key");
  }

  // Create EVP_PKEY for the peer
  EVP_PKEY_ptr peerPkey(EVP_PKEY_new(), EVP_PKEY_free);
  if (!peerPkey) {
    throw std::runtime_error("ECDH: failed to create peer EVP_PKEY");
  }

  // EVP_PKEY_assign_EC_KEY takes ownership of ecKey on success
  if (EVP_PKEY_assign_EC_KEY(peerPkey.get(), ecKey.get()) != 1) {
    throw std::runtime_error("ECDH: failed to assign EC_KEY to EVP_PKEY");
  }
  ecKey.release(); // EVP_PKEY now owns the EC_KEY

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

  const EC_KEY* ec = EVP_PKEY_get0_EC_KEY(_pkey.get());
  if (!ec) {
    throw std::runtime_error("ECDH: key is not an EC key");
  }

  const BIGNUM* priv = EC_KEY_get0_private_key(ec);
  if (!priv) {
    throw std::runtime_error("ECDH: no private key available");
  }

  int len = BN_num_bytes(priv);
  std::vector<uint8_t> buf(len);
  BN_bn2bin(priv, buf.data());

  return ToNativeArrayBuffer(buf);
}

void HybridECDH::setPrivateKey(const std::shared_ptr<ArrayBuffer>& privateKey) {
  ensureInitialized();

  // Create new EC_KEY
  EC_KEY_ptr ecKey(EC_KEY_new(), EC_KEY_free);
  if (!ecKey) {
    throw std::runtime_error("ECDH: failed to create EC_KEY");
  }

  if (EC_KEY_set_group(ecKey.get(), _group.get()) != 1) {
    throw std::runtime_error("ECDH: failed to set EC group");
  }

  // Convert private key bytes to BIGNUM
  BN_ptr privBn(BN_bin2bn(privateKey->data(), static_cast<int>(privateKey->size()), nullptr), BN_free);
  if (!privBn) {
    throw std::runtime_error("ECDH: failed to convert private key");
  }

  // Calculate public key from private key
  EC_POINT_ptr pubPoint(EC_POINT_new(_group.get()), EC_POINT_free);
  if (!pubPoint) {
    throw std::runtime_error("ECDH: failed to create EC point");
  }

  if (EC_POINT_mul(_group.get(), pubPoint.get(), privBn.get(), nullptr, nullptr, nullptr) != 1) {
    throw std::runtime_error("ECDH: failed to compute public key from private key");
  }

  // Set keys on EC_KEY (these functions copy the values, so we still own privBn and pubPoint)
  if (EC_KEY_set_private_key(ecKey.get(), privBn.get()) != 1) {
    throw std::runtime_error("ECDH: failed to set private key");
  }

  if (EC_KEY_set_public_key(ecKey.get(), pubPoint.get()) != 1) {
    throw std::runtime_error("ECDH: failed to set public key");
  }

  // Create new EVP_PKEY
  EVP_PKEY_ptr pkey(EVP_PKEY_new(), EVP_PKEY_free);
  if (!pkey) {
    throw std::runtime_error("ECDH: failed to create EVP_PKEY");
  }

  // EVP_PKEY_assign_EC_KEY takes ownership of ecKey on success
  if (EVP_PKEY_assign_EC_KEY(pkey.get(), ecKey.get()) != 1) {
    throw std::runtime_error("ECDH: failed to assign EC_KEY to EVP_PKEY");
  }
  ecKey.release(); // EVP_PKEY now owns the EC_KEY

  _pkey = std::move(pkey);
}

std::shared_ptr<ArrayBuffer> HybridECDH::getPublicKey() {
  if (!_pkey) {
    throw std::runtime_error("ECDH: no key set");
  }

  const EC_KEY* ec = EVP_PKEY_get0_EC_KEY(_pkey.get());
  if (!ec) {
    throw std::runtime_error("ECDH: key is not an EC key");
  }

  const EC_POINT* point = EC_KEY_get0_public_key(ec);
  const EC_GROUP* group = EC_KEY_get0_group(ec);
  if (!point || !group) {
    throw std::runtime_error("ECDH: incomplete key");
  }

  // Get uncompressed public key size
  size_t len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
  if (len == 0) {
    throw std::runtime_error("ECDH: failed to get public key length");
  }

  std::vector<uint8_t> buf(len);
  if (EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, buf.data(), len, nullptr) == 0) {
    throw std::runtime_error("ECDH: failed to encode public key");
  }

  return ToNativeArrayBuffer(buf);
}

void HybridECDH::setPublicKey(const std::shared_ptr<ArrayBuffer>& publicKey) {
  ensureInitialized();

  // Create EC_POINT from the public key bytes
  EC_POINT_ptr point(EC_POINT_new(_group.get()), EC_POINT_free);
  if (!point) {
    throw std::runtime_error("ECDH: failed to create EC point");
  }

  if (EC_POINT_oct2point(_group.get(), point.get(), publicKey->data(), publicKey->size(), nullptr) != 1) {
    throw std::runtime_error("ECDH: invalid public key");
  }

  // Create new EC_KEY
  EC_KEY_ptr ecKey(EC_KEY_new(), EC_KEY_free);
  if (!ecKey) {
    throw std::runtime_error("ECDH: failed to create EC_KEY");
  }

  if (EC_KEY_set_group(ecKey.get(), _group.get()) != 1) {
    throw std::runtime_error("ECDH: failed to set EC group");
  }

  if (EC_KEY_set_public_key(ecKey.get(), point.get()) != 1) {
    throw std::runtime_error("ECDH: failed to set public key");
  }

  // Create new EVP_PKEY
  EVP_PKEY_ptr pkey(EVP_PKEY_new(), EVP_PKEY_free);
  if (!pkey) {
    throw std::runtime_error("ECDH: failed to create EVP_PKEY");
  }

  // EVP_PKEY_assign_EC_KEY takes ownership of ecKey on success
  if (EVP_PKEY_assign_EC_KEY(pkey.get(), ecKey.get()) != 1) {
    throw std::runtime_error("ECDH: failed to assign EC_KEY to EVP_PKEY");
  }
  ecKey.release(); // EVP_PKEY now owns the EC_KEY

  _pkey = std::move(pkey);
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

#pragma clang diagnostic pop

} // namespace margelo::nitro::crypto
