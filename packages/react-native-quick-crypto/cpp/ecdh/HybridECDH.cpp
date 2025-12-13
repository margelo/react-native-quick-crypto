#include "HybridECDH.hpp"
#include "Utils.hpp"
#include <NitroModules/ArrayBuffer.hpp>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <stdexcept>

namespace margelo::nitro::crypto {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

void HybridECDH::init(const std::string& curveName) {
  _curveName = curveName;
  _curveNid = getCurveNid(curveName);
  if (_curveNid == NID_undef) {
    throw std::runtime_error("Unknown curve name: " + curveName);
  }

  // Clear previous key if any
  if (_pkey) {
    EVP_PKEY_free(_pkey);
    _pkey = nullptr;
  }

  if (_group) {
    EC_GROUP_free(_group);
    _group = nullptr;
  }

  _group = EC_GROUP_new_by_curve_name(_curveNid);
  if (!_group) {
    throw std::runtime_error("Failed to create EC group for curve: " + curveName);
  }
}

std::shared_ptr<ArrayBuffer> HybridECDH::generateKeys() {
  ensureInitialized();

  std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free);
  if (!ctx)
    throw std::runtime_error("Failed to create context");

  if (EVP_PKEY_keygen_init(ctx.get()) <= 0)
    throw std::runtime_error("Failed to init keygen");
  if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), _curveNid) <= 0)
    throw std::runtime_error("Failed to set curve");

  EVP_PKEY* pkey = nullptr;
  if (EVP_PKEY_keygen(ctx.get(), &pkey) <= 0)
    throw std::runtime_error("Failed to generate key");

  if (_pkey)
    EVP_PKEY_free(_pkey);
  _pkey = pkey;

  return getPublicKey();
}

std::shared_ptr<ArrayBuffer> HybridECDH::computeSecret(const std::shared_ptr<ArrayBuffer>& otherPublicKey) {
  ensureInitialized();
  if (!_pkey)
    throw std::runtime_error("Private key not set");

  // Create peer key from buffer
  const unsigned char* p = otherPublicKey->data();
  // Node.js usually passes uncompressed or compressed point. We need to convert it to EVP_PKEY.
  // We can use EC_KEY and then assign to EVP_PKEY.

  // Use cached group
  // std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)> group(EC_GROUP_new_by_curve_name(_curveNid), EC_GROUP_free);
  // if (!group)
  //   throw std::runtime_error("Failed to create group");

  std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)> point(EC_POINT_new(_group), EC_POINT_free);
  if (!point)
    throw std::runtime_error("Failed to create point");

  if (EC_POINT_oct2point(_group, point.get(), p, otherPublicKey->size(), nullptr) != 1) {
    throw std::runtime_error("Failed to decode public key point");
  }

  std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)> ec_key(EC_KEY_new(), EC_KEY_free);
  if (!ec_key)
    throw std::runtime_error("Failed to create EC_KEY");
  if (EC_KEY_set_group(ec_key.get(), _group) != 1)
    throw std::runtime_error("Failed to set group");
  if (EC_KEY_set_public_key(ec_key.get(), point.get()) != 1)
    throw std::runtime_error("Failed to set public key");

  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> peer_pkey(EVP_PKEY_new(), EVP_PKEY_free);
  if (EVP_PKEY_assign_EC_KEY(peer_pkey.get(), ec_key.release()) != 1)
    throw std::runtime_error("Failed to assign EC_KEY");

  // Derive
  std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(EVP_PKEY_CTX_new(_pkey, nullptr), EVP_PKEY_CTX_free);
  if (!ctx)
    throw std::runtime_error("Failed to create derive context");

  if (EVP_PKEY_derive_init(ctx.get()) <= 0)
    throw std::runtime_error("Failed to init derive");
  if (EVP_PKEY_derive_set_peer(ctx.get(), peer_pkey.get()) <= 0)
    throw std::runtime_error("Failed to set peer key");

  size_t secret_len;
  if (EVP_PKEY_derive(ctx.get(), nullptr, &secret_len) <= 0)
    throw std::runtime_error("Failed to get secret length");

  std::vector<uint8_t> secret(secret_len);
  if (EVP_PKEY_derive(ctx.get(), secret.data(), &secret_len) <= 0)
    throw std::runtime_error("Failed to derive secret");

  return ToNativeArrayBuffer(std::string(secret.begin(), secret.end())); // Utils.hpp
}

std::shared_ptr<ArrayBuffer> HybridECDH::getPrivateKey() {
  if (!_pkey)
    throw std::runtime_error("No key set");
  // Implement logic to extract private key (usually big number or buffer)
  const EC_KEY* ec = EVP_PKEY_get0_EC_KEY(_pkey);
  if (!ec)
    throw std::runtime_error("Not an EC key");
  const BIGNUM* priv = EC_KEY_get0_private_key(ec);
  if (!priv)
    throw std::runtime_error("No private key component");

  int len = BN_num_bytes(priv);
  std::vector<uint8_t> buf(len);
  BN_bn2bin(priv, buf.data());
  return ToNativeArrayBuffer(std::string(buf.begin(), buf.end()));
}

void HybridECDH::setPrivateKey(const std::shared_ptr<ArrayBuffer>& privateKey) {
  ensureInitialized();
  // Use cached group
  // auto group = std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)>(EC_GROUP_new_by_curve_name(_curveNid), EC_GROUP_free);
  auto ec = std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)>(EC_KEY_new(), EC_KEY_free);
  EC_KEY_set_group(ec.get(), _group);

  BIGNUM* priv_bn = BN_bin2bn(privateKey->data(), static_cast<int>(privateKey->size()), nullptr);
  if (!priv_bn)
    throw std::runtime_error("Failed to convert private key");
  // Should set public key too if possible, but Node.js allows just private.

  // Calculate public key from private
  auto point = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>(EC_POINT_new(_group), EC_POINT_free);
  EC_POINT_mul(_group, point.get(), priv_bn, nullptr, nullptr, nullptr);

  EC_KEY_set_private_key(ec.get(), priv_bn);
  EC_KEY_set_public_key(ec.get(), point.get());
  BN_free(priv_bn);

  if (_pkey)
    EVP_PKEY_free(_pkey);
  _pkey = EVP_PKEY_new();
  EVP_PKEY_assign_EC_KEY(_pkey, ec.release());
}

std::shared_ptr<ArrayBuffer> HybridECDH::getPublicKey() {
  if (!_pkey)
    throw std::runtime_error("No key set");
  const EC_KEY* ec = EVP_PKEY_get0_EC_KEY(_pkey);
  if (!ec)
    throw std::runtime_error("Not an EC key");
  const EC_POINT* point = EC_KEY_get0_public_key(ec);
  const EC_GROUP* group = EC_KEY_get0_group(ec);
  if (!point || !group)
    throw std::runtime_error("Incomplete key");

  // Default to uncompressed
  size_t len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
  if (len == 0)
    throw std::runtime_error("Failed to get pubkey length");
  std::vector<uint8_t> buf(len);
  if (EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, buf.data(), len, nullptr) == 0) {
    throw std::runtime_error("Failed to encode pubkey");
  }
  return ToNativeArrayBuffer(std::string(buf.begin(), buf.end()));
}

void HybridECDH::setPublicKey(const std::shared_ptr<ArrayBuffer>& publicKey) {
  ensureInitialized();
  // Cannot set ONLY public key on an ECDH object usually intended for own keys,
  // but Node.js allows it? Or is this for "other" key usually?
  // Node.js setPublicKey sets the public key of the ECDH object.

  // Use cached group
  // auto group = std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)>(EC_GROUP_new_by_curve_name(_curveNid), EC_GROUP_free);
  auto point = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>(EC_POINT_new(_group), EC_POINT_free);

  if (EC_POINT_oct2point(_group, point.get(), (const unsigned char*)publicKey->data(), publicKey->size(), nullptr) != 1) {
    throw std::runtime_error("Invalid public key");
  }

  auto ec = std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)>(EC_KEY_new(), EC_KEY_free);
  EC_KEY_set_group(ec.get(), _group);
  EC_KEY_set_public_key(ec.get(), point.get());

  if (_pkey)
    EVP_PKEY_free(_pkey);
  _pkey = EVP_PKEY_new();
  EVP_PKEY_assign_EC_KEY(_pkey, ec.release());
}

void HybridECDH::ensureInitialized() {
  if (_curveNid == 0 || !_group) {
    throw std::runtime_error("ECDH not initialized");
  }
}

int HybridECDH::getCurveNid(const std::string& name) {
  int nid = OBJ_txt2nid(name.c_str());
  if (nid == NID_undef)
    nid = OBJ_sn2nid(name.c_str());
  if (nid == NID_undef)
    nid = OBJ_ln2nid(name.c_str());
  return nid;
}

#pragma clang diagnostic pop
} // namespace margelo::nitro::crypto
