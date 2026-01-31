#include "HybridDiffieHellman.hpp"
#include "QuickCryptoUtils.hpp"
#include <NitroModules/ArrayBuffer.hpp>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdexcept>

namespace margelo::nitro::crypto {

// Smart pointer type aliases for RAII
using BN_ptr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using DH_ptr = std::unique_ptr<DH, decltype(&DH_free)>;
using EVP_PKEY_CTX_ptr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

// Minimum DH prime size for security (2048 bits = 256 bytes)
static constexpr int kMinDHPrimeBits = 2048;

// Suppress deprecation warnings for DH_* functions
// Node.js ncrypto uses the same pattern - these APIs work but are deprecated in OpenSSL 3.x
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

void HybridDiffieHellman::init(const std::shared_ptr<ArrayBuffer>& prime, const std::shared_ptr<ArrayBuffer>& generator) {
  // Create DH structure
  DH_ptr dh(DH_new(), DH_free);
  if (!dh) {
    throw std::runtime_error("DiffieHellman: failed to create DH structure");
  }

  // Convert prime and generator to BIGNUMs
  BIGNUM* p = BN_bin2bn(prime->data(), static_cast<int>(prime->size()), nullptr);
  BIGNUM* g = BN_bin2bn(generator->data(), static_cast<int>(generator->size()), nullptr);

  if (!p || !g) {
    if (p)
      BN_free(p);
    if (g)
      BN_free(g);
    throw std::runtime_error("DiffieHellman: failed to convert parameters to BIGNUM");
  }

  // DH_set0_pqg takes ownership of p and g on success
  if (DH_set0_pqg(dh.get(), p, nullptr, g) != 1) {
    BN_free(p);
    BN_free(g);
    throw std::runtime_error("DiffieHellman: failed to set DH parameters");
  }

  // Create EVP_PKEY and assign DH to it
  EVP_PKEY_ptr pkey(EVP_PKEY_new(), EVP_PKEY_free);
  if (!pkey) {
    throw std::runtime_error("DiffieHellman: failed to create EVP_PKEY");
  }

  // EVP_PKEY_assign_DH takes ownership of dh on success
  if (EVP_PKEY_assign_DH(pkey.get(), dh.get()) != 1) {
    throw std::runtime_error("DiffieHellman: failed to assign DH to EVP_PKEY");
  }
  dh.release(); // EVP_PKEY now owns the DH

  _pkey = std::move(pkey);
}

void HybridDiffieHellman::initWithSize(double primeLength, double generator) {
  int primeBits = static_cast<int>(primeLength);
  int gen = static_cast<int>(generator);

  // Validate minimum key size for security
  if (primeBits < kMinDHPrimeBits) {
    throw std::runtime_error("DiffieHellman: prime length must be at least 2048 bits");
  }

  // Create parameter generation context
  EVP_PKEY_CTX_ptr pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_DH, nullptr), EVP_PKEY_CTX_free);
  if (!pctx) {
    throw std::runtime_error("DiffieHellman: failed to create parameter context");
  }

  if (EVP_PKEY_paramgen_init(pctx.get()) <= 0) {
    throw std::runtime_error("DiffieHellman: failed to initialize parameter generation");
  }

  if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(pctx.get(), primeBits) <= 0) {
    throw std::runtime_error("DiffieHellman: failed to set prime length");
  }

  if (EVP_PKEY_CTX_set_dh_paramgen_generator(pctx.get(), gen) <= 0) {
    throw std::runtime_error("DiffieHellman: failed to set generator");
  }

  EVP_PKEY* params = nullptr;
  if (EVP_PKEY_paramgen(pctx.get(), &params) <= 0) {
    throw std::runtime_error("DiffieHellman: failed to generate parameters");
  }

  _pkey.reset(params);
}

std::shared_ptr<ArrayBuffer> HybridDiffieHellman::generateKeys() {
  ensureInitialized();

  EVP_PKEY_CTX_ptr kctx(EVP_PKEY_CTX_new(_pkey.get(), nullptr), EVP_PKEY_CTX_free);
  if (!kctx) {
    throw std::runtime_error("DiffieHellman: failed to create keygen context");
  }

  if (EVP_PKEY_keygen_init(kctx.get()) <= 0) {
    throw std::runtime_error("DiffieHellman: failed to initialize key generation");
  }

  EVP_PKEY* newKey = nullptr;
  if (EVP_PKEY_keygen(kctx.get(), &newKey) <= 0) {
    throw std::runtime_error("DiffieHellman: failed to generate key pair");
  }

  // Replace parameters-only key with full key (which includes parameters)
  _pkey.reset(newKey);

  return getPublicKey();
}

std::shared_ptr<ArrayBuffer> HybridDiffieHellman::computeSecret(const std::shared_ptr<ArrayBuffer>& otherPublicKey) {
  ensureInitialized();

  const DH* ourDh = getDH();
  const BIGNUM *p, *q, *g;
  DH_get0_pqg(ourDh, &p, &q, &g);

  // Create peer DH with same parameters but peer's public key
  DH_ptr peerDh(DH_new(), DH_free);
  if (!peerDh) {
    throw std::runtime_error("DiffieHellman: failed to create peer DH structure");
  }

  // Duplicate parameters for peer
  BIGNUM* peerP = BN_dup(p);
  BIGNUM* peerG = BN_dup(g);
  BIGNUM* peerPubKey = BN_bin2bn(otherPublicKey->data(), static_cast<int>(otherPublicKey->size()), nullptr);

  if (!peerP || !peerG || !peerPubKey) {
    if (peerP)
      BN_free(peerP);
    if (peerG)
      BN_free(peerG);
    if (peerPubKey)
      BN_free(peerPubKey);
    throw std::runtime_error("DiffieHellman: failed to create peer parameters");
  }

  // Set peer DH parameters (takes ownership on success)
  if (DH_set0_pqg(peerDh.get(), peerP, nullptr, peerG) != 1) {
    BN_free(peerP);
    BN_free(peerG);
    BN_free(peerPubKey);
    throw std::runtime_error("DiffieHellman: failed to set peer DH parameters");
  }

  // Set peer public key (takes ownership on success)
  if (DH_set0_key(peerDh.get(), peerPubKey, nullptr) != 1) {
    BN_free(peerPubKey);
    throw std::runtime_error("DiffieHellman: failed to set peer public key");
  }

  // Create peer EVP_PKEY
  EVP_PKEY_ptr peerPkey(EVP_PKEY_new(), EVP_PKEY_free);
  if (!peerPkey) {
    throw std::runtime_error("DiffieHellman: failed to create peer EVP_PKEY");
  }

  // EVP_PKEY_assign_DH takes ownership of peerDh on success
  if (EVP_PKEY_assign_DH(peerPkey.get(), peerDh.get()) != 1) {
    throw std::runtime_error("DiffieHellman: failed to assign peer DH to EVP_PKEY");
  }
  peerDh.release(); // EVP_PKEY now owns the DH

  // Derive shared secret using EVP API
  EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new(_pkey.get(), nullptr), EVP_PKEY_CTX_free);
  if (!ctx) {
    throw std::runtime_error("DiffieHellman: failed to create derive context");
  }

  if (EVP_PKEY_derive_init(ctx.get()) <= 0) {
    throw std::runtime_error("DiffieHellman: failed to initialize key derivation");
  }

  if (EVP_PKEY_derive_set_peer(ctx.get(), peerPkey.get()) <= 0) {
    throw std::runtime_error("DiffieHellman: failed to set peer key for derivation");
  }

  // Get required buffer size
  size_t secretLen = 0;
  if (EVP_PKEY_derive(ctx.get(), nullptr, &secretLen) <= 0) {
    throw std::runtime_error("DiffieHellman: failed to get shared secret length");
  }

  // Derive the shared secret
  std::vector<uint8_t> secret(secretLen);
  if (EVP_PKEY_derive(ctx.get(), secret.data(), &secretLen) <= 0) {
    throw std::runtime_error("DiffieHellman: failed to derive shared secret");
  }

  // Resize to actual length (may be smaller due to leading zeros)
  secret.resize(secretLen);

  return ToNativeArrayBuffer(secret);
}

std::shared_ptr<ArrayBuffer> HybridDiffieHellman::getPrime() {
  ensureInitialized();
  const DH* dh = getDH();

  const BIGNUM *p, *q, *g;
  DH_get0_pqg(dh, &p, &q, &g);
  if (!p) {
    throw std::runtime_error("DiffieHellman: no prime available");
  }

  int len = BN_num_bytes(p);
  std::vector<uint8_t> buf(len);
  BN_bn2bin(p, buf.data());

  return ToNativeArrayBuffer(buf);
}

std::shared_ptr<ArrayBuffer> HybridDiffieHellman::getGenerator() {
  ensureInitialized();
  const DH* dh = getDH();

  const BIGNUM *p, *q, *g;
  DH_get0_pqg(dh, &p, &q, &g);
  if (!g) {
    throw std::runtime_error("DiffieHellman: no generator available");
  }

  int len = BN_num_bytes(g);
  std::vector<uint8_t> buf(len);
  BN_bn2bin(g, buf.data());

  return ToNativeArrayBuffer(buf);
}

std::shared_ptr<ArrayBuffer> HybridDiffieHellman::getPublicKey() {
  ensureInitialized();
  const DH* dh = getDH();

  const BIGNUM *pub, *priv;
  DH_get0_key(dh, &pub, &priv);
  if (!pub) {
    throw std::runtime_error("DiffieHellman: no public key available");
  }

  int len = BN_num_bytes(pub);
  std::vector<uint8_t> buf(len);
  BN_bn2bin(pub, buf.data());

  return ToNativeArrayBuffer(buf);
}

std::shared_ptr<ArrayBuffer> HybridDiffieHellman::getPrivateKey() {
  ensureInitialized();
  const DH* dh = getDH();

  const BIGNUM *pub, *priv;
  DH_get0_key(dh, &pub, &priv);
  if (!priv) {
    throw std::runtime_error("DiffieHellman: no private key available");
  }

  int len = BN_num_bytes(priv);
  std::vector<uint8_t> buf(len);
  BN_bn2bin(priv, buf.data());

  return ToNativeArrayBuffer(buf);
}

void HybridDiffieHellman::setPublicKey(const std::shared_ptr<ArrayBuffer>& publicKey) {
  ensureInitialized();
  const DH* dh = getDH();

  // Get existing keys
  const BIGNUM *oldPub, *oldPriv;
  DH_get0_key(dh, &oldPub, &oldPriv);

  // Get parameters
  const BIGNUM *p, *q, *g;
  DH_get0_pqg(dh, &p, &q, &g);

  // Create new DH with copied parameters
  DH_ptr newDh(DH_new(), DH_free);
  if (!newDh) {
    throw std::runtime_error("DiffieHellman: failed to create new DH structure");
  }

  // Duplicate parameters
  BIGNUM* newP = BN_dup(p);
  BIGNUM* newQ = q ? BN_dup(q) : nullptr;
  BIGNUM* newG = BN_dup(g);

  if (!newP || !newG) {
    if (newP)
      BN_free(newP);
    if (newQ)
      BN_free(newQ);
    if (newG)
      BN_free(newG);
    throw std::runtime_error("DiffieHellman: failed to duplicate parameters");
  }

  if (DH_set0_pqg(newDh.get(), newP, newQ, newG) != 1) {
    BN_free(newP);
    if (newQ)
      BN_free(newQ);
    BN_free(newG);
    throw std::runtime_error("DiffieHellman: failed to set parameters");
  }

  // Convert new public key
  BIGNUM* newPub = BN_bin2bn(publicKey->data(), static_cast<int>(publicKey->size()), nullptr);
  BIGNUM* newPriv = oldPriv ? BN_dup(oldPriv) : nullptr;

  if (!newPub) {
    if (newPriv)
      BN_free(newPriv);
    throw std::runtime_error("DiffieHellman: failed to convert public key");
  }

  if (DH_set0_key(newDh.get(), newPub, newPriv) != 1) {
    BN_free(newPub);
    if (newPriv)
      BN_free(newPriv);
    throw std::runtime_error("DiffieHellman: failed to set keys");
  }

  // Create new EVP_PKEY
  EVP_PKEY_ptr newPkey(EVP_PKEY_new(), EVP_PKEY_free);
  if (!newPkey) {
    throw std::runtime_error("DiffieHellman: failed to create new EVP_PKEY");
  }

  if (EVP_PKEY_assign_DH(newPkey.get(), newDh.get()) != 1) {
    throw std::runtime_error("DiffieHellman: failed to assign DH to EVP_PKEY");
  }
  newDh.release();

  _pkey = std::move(newPkey);
}

void HybridDiffieHellman::setPrivateKey(const std::shared_ptr<ArrayBuffer>& privateKey) {
  ensureInitialized();
  const DH* dh = getDH();

  // Get existing keys
  const BIGNUM *oldPub, *oldPriv;
  DH_get0_key(dh, &oldPub, &oldPriv);

  // Get parameters
  const BIGNUM *p, *q, *g;
  DH_get0_pqg(dh, &p, &q, &g);

  // Create new DH with copied parameters
  DH_ptr newDh(DH_new(), DH_free);
  if (!newDh) {
    throw std::runtime_error("DiffieHellman: failed to create new DH structure");
  }

  // Duplicate parameters
  BIGNUM* newP = BN_dup(p);
  BIGNUM* newQ = q ? BN_dup(q) : nullptr;
  BIGNUM* newG = BN_dup(g);

  if (!newP || !newG) {
    if (newP)
      BN_free(newP);
    if (newQ)
      BN_free(newQ);
    if (newG)
      BN_free(newG);
    throw std::runtime_error("DiffieHellman: failed to duplicate parameters");
  }

  if (DH_set0_pqg(newDh.get(), newP, newQ, newG) != 1) {
    BN_free(newP);
    if (newQ)
      BN_free(newQ);
    BN_free(newG);
    throw std::runtime_error("DiffieHellman: failed to set parameters");
  }

  // Convert new private key
  BIGNUM* newPub = oldPub ? BN_dup(oldPub) : nullptr;
  BIGNUM* newPriv = BN_bin2bn(privateKey->data(), static_cast<int>(privateKey->size()), nullptr);

  if (!newPriv) {
    if (newPub)
      BN_free(newPub);
    throw std::runtime_error("DiffieHellman: failed to convert private key");
  }

  if (DH_set0_key(newDh.get(), newPub, newPriv) != 1) {
    if (newPub)
      BN_free(newPub);
    BN_free(newPriv);
    throw std::runtime_error("DiffieHellman: failed to set keys");
  }

  // Create new EVP_PKEY
  EVP_PKEY_ptr newPkey(EVP_PKEY_new(), EVP_PKEY_free);
  if (!newPkey) {
    throw std::runtime_error("DiffieHellman: failed to create new EVP_PKEY");
  }

  if (EVP_PKEY_assign_DH(newPkey.get(), newDh.get()) != 1) {
    throw std::runtime_error("DiffieHellman: failed to assign DH to EVP_PKEY");
  }
  newDh.release();

  _pkey = std::move(newPkey);
}

void HybridDiffieHellman::ensureInitialized() const {
  if (!_pkey) {
    throw std::runtime_error("DiffieHellman: not initialized");
  }
}

const DH* HybridDiffieHellman::getDH() const {
  const DH* dh = EVP_PKEY_get0_DH(_pkey.get());
  if (!dh) {
    throw std::runtime_error("DiffieHellman: key is not a DH key");
  }
  return dh;
}

#pragma clang diagnostic pop

} // namespace margelo::nitro::crypto
