#include "HybridDiffieHellman.hpp"
#include "Utils.hpp"
#include <NitroModules/ArrayBuffer.hpp>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdexcept>

namespace margelo::nitro::crypto {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

void HybridDiffieHellman::init(const std::shared_ptr<ArrayBuffer>& prime, const std::shared_ptr<ArrayBuffer>& generator) {
  if (_pkey) {
    EVP_PKEY_free(_pkey);
    _pkey = nullptr;
  }

  // Create DH parameters from prime and generator
  DH* dh = DH_new();
  if (!dh)
    throw std::runtime_error("Failed to create DH");

  BIGNUM* p = BN_bin2bn(prime->data(), static_cast<int>(prime->size()), nullptr);
  BIGNUM* g = BN_bin2bn(generator->data(), static_cast<int>(generator->size()), nullptr);

  if (!p || !g) {
    DH_free(dh);
    if (p)
      BN_free(p);
    if (g)
      BN_free(g);
    throw std::runtime_error("Failed to convert parameters to BIGNUM");
  }

  if (DH_set0_pqg(dh, p, nullptr, g) != 1) {
    DH_free(dh);
    BN_free(p);
    BN_free(g); // DH_set0_pqg takes ownership only on success.
    throw std::runtime_error("Failed to set DH parameters");
  }

  _pkey = EVP_PKEY_new();
  if (!_pkey) {
    DH_free(dh);
    throw std::runtime_error("Failed to create EVP_PKEY");
  }

  if (EVP_PKEY_assign_DH(_pkey, dh) != 1) {
    EVP_PKEY_free(_pkey);
    _pkey = nullptr;
    DH_free(dh); // Assign takes ownership
    throw std::runtime_error("Failed to assign DH to EVP_PKEY");
  }
}

void HybridDiffieHellman::initWithSize(double primeLength, double generator) {
  if (_pkey) {
    EVP_PKEY_free(_pkey);
    _pkey = nullptr;
  }

  // Generate parameters
  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, nullptr);
  if (!pctx)
    throw std::runtime_error("Failed to create context");

  if (EVP_PKEY_paramgen_init(pctx) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    throw std::runtime_error("Failed to init paramgen");
  }

  if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(pctx, (int)primeLength) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    throw std::runtime_error("Failed to set prime length");
  }

  if (EVP_PKEY_CTX_set_dh_paramgen_generator(pctx, (int)generator) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    throw std::runtime_error("Failed to set generator");
  }

  EVP_PKEY* params = nullptr;
  if (EVP_PKEY_paramgen(pctx, &params) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    throw std::runtime_error("Failed to generate parameters");
  }

  EVP_PKEY_CTX_free(pctx);
  _pkey = params;
}

std::shared_ptr<ArrayBuffer> HybridDiffieHellman::generateKeys() {
  ensureInitialized();

  EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new(_pkey, nullptr);
  if (!kctx)
    throw std::runtime_error("Failed to create keygen context");

  if (EVP_PKEY_keygen_init(kctx) <= 0) {
    EVP_PKEY_CTX_free(kctx);
    throw std::runtime_error("Failed to init keygen");
  }

  EVP_PKEY* new_key = nullptr;
  if (EVP_PKEY_keygen(kctx, &new_key) <= 0) {
    EVP_PKEY_CTX_free(kctx);
    throw std::runtime_error("Failed to generate key");
  }

  EVP_PKEY_CTX_free(kctx);

  // Replace parameters-only key with full key (which includes parameters)
  EVP_PKEY_free(_pkey);
  _pkey = new_key;

  return getPublicKey();
}

std::shared_ptr<ArrayBuffer> HybridDiffieHellman::computeSecret(const std::shared_ptr<ArrayBuffer>& otherPublicKey) {
  ensureInitialized();

  // Create peer key from public key buffer
  // We need to create a new EVP_PKEY with the same parameters as ours, but with the peer's public key.

  const DH* our_dh = EVP_PKEY_get0_DH(_pkey);
  if (!our_dh)
    throw std::runtime_error("Not a DH key");

  const BIGNUM *p, *q, *g;
  DH_get0_pqg(our_dh, &p, &q, &g);

  DH* peer_dh = DH_new();
  BIGNUM* peer_p = BN_dup(p);
  BIGNUM* peer_g = BN_dup(g);
  BIGNUM* peer_pub_key = BN_bin2bn(otherPublicKey->data(), static_cast<int>(otherPublicKey->size()), nullptr);

  if (!peer_dh || !peer_p || !peer_g || !peer_pub_key) {
    DH_free(peer_dh);
    BN_free(peer_p);
    BN_free(peer_g);
    BN_free(peer_pub_key);
    throw std::runtime_error("Failed to create peer DH");
  }

  DH_set0_pqg(peer_dh, peer_p, nullptr, peer_g);
  DH_set0_key(peer_dh, peer_pub_key, nullptr);

  EVP_PKEY* peer_pkey = EVP_PKEY_new();
  EVP_PKEY_assign_DH(peer_pkey, peer_dh);

  // Derive
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(_pkey, nullptr);
  if (!ctx || EVP_PKEY_derive_init(ctx) <= 0 || EVP_PKEY_derive_set_peer(ctx, peer_pkey) <= 0) {
    if (ctx)
      EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_pkey);
    throw std::runtime_error("Failed to init derive");
  }

  size_t secret_len;
  if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_pkey);
    throw std::runtime_error("Failed to get secret length");
  }

  std::vector<uint8_t> secret(secret_len);
  if (EVP_PKEY_derive(ctx, secret.data(), &secret_len) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_pkey);
    throw std::runtime_error("Failed to derive");
  }

  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(peer_pkey);

  return ToNativeArrayBuffer(std::string(secret.begin(), secret.end()));
}

std::shared_ptr<ArrayBuffer> HybridDiffieHellman::getPrime() {
  ensureInitialized();
  const DH* dh = EVP_PKEY_get0_DH(_pkey);
  const BIGNUM *p, *q, *g;
  DH_get0_pqg(dh, &p, &q, &g);
  if (!p)
    throw std::runtime_error("No prime");

  int len = BN_num_bytes(p);
  std::vector<uint8_t> buf(len);
  BN_bn2bin(p, buf.data());
  return ToNativeArrayBuffer(std::string(buf.begin(), buf.end()));
}

std::shared_ptr<ArrayBuffer> HybridDiffieHellman::getGenerator() {
  ensureInitialized();
  const DH* dh = EVP_PKEY_get0_DH(_pkey);
  const BIGNUM *p, *q, *g;
  DH_get0_pqg(dh, &p, &q, &g);
  if (!g)
    throw std::runtime_error("No generator");

  int len = BN_num_bytes(g);
  std::vector<uint8_t> buf(len);
  BN_bn2bin(g, buf.data());
  return ToNativeArrayBuffer(std::string(buf.begin(), buf.end()));
}

std::shared_ptr<ArrayBuffer> HybridDiffieHellman::getPublicKey() {
  ensureInitialized();
  const DH* dh = EVP_PKEY_get0_DH(_pkey);
  const BIGNUM *pub, *priv;
  DH_get0_key(dh, &pub, &priv);
  if (!pub)
    throw std::runtime_error("No public key");

  int len = BN_num_bytes(pub);
  std::vector<uint8_t> buf(len);
  BN_bn2bin(pub, buf.data());
  return ToNativeArrayBuffer(std::string(buf.begin(), buf.end()));
}

std::shared_ptr<ArrayBuffer> HybridDiffieHellman::getPrivateKey() {
  ensureInitialized();
  const DH* dh = EVP_PKEY_get0_DH(_pkey);
  const BIGNUM *pub, *priv;
  DH_get0_key(dh, &pub, &priv);
  if (!priv)
    throw std::runtime_error("No private key");

  int len = BN_num_bytes(priv);
  std::vector<uint8_t> buf(len);
  BN_bn2bin(priv, buf.data());
  return ToNativeArrayBuffer(std::string(buf.begin(), buf.end()));
}

void HybridDiffieHellman::setPublicKey(const std::shared_ptr<ArrayBuffer>& publicKey) {
  ensureInitialized();
  const DH* dh = EVP_PKEY_get0_DH(_pkey);
  BIGNUM* pub = BN_bin2bn(publicKey->data(), static_cast<int>(publicKey->size()), nullptr);
  if (!pub)
    throw std::runtime_error("Failed to convert public key");

  // We need to keep private key if it exists
  const BIGNUM *old_pub, *old_priv;
  DH_get0_key(dh, &old_pub, &old_priv);

  BIGNUM* priv = old_priv ? BN_dup(old_priv) : nullptr;

  // Since dh is const, we need to replace the whole key or cast away const (dangerous).
  // Better: Create new DH, copy params, set new keys, replace EVP_PKEY.
  DH* new_dh = DH_new();
  const BIGNUM *p, *q, *g;
  DH_get0_pqg(dh, &p, &q, &g);
  DH_set0_pqg(new_dh, BN_dup(p), q ? BN_dup(q) : nullptr, BN_dup(g));
  DH_set0_key(new_dh, pub, priv);

  EVP_PKEY_free(_pkey);
  _pkey = EVP_PKEY_new();
  EVP_PKEY_assign_DH(_pkey, new_dh);
}

void HybridDiffieHellman::setPrivateKey(const std::shared_ptr<ArrayBuffer>& privateKey) {
  ensureInitialized();
  const DH* dh = EVP_PKEY_get0_DH(_pkey);
  BIGNUM* priv = BN_bin2bn(privateKey->data(), static_cast<int>(privateKey->size()), nullptr);
  if (!priv)
    throw std::runtime_error("Failed to convert private key");

  // We need to keep public key if it exists
  const BIGNUM *old_pub, *old_priv;
  DH_get0_key(dh, &old_pub, &old_priv);

  BIGNUM* pub = old_pub ? BN_dup(old_pub) : nullptr;

  DH* new_dh = DH_new();
  const BIGNUM *p, *q, *g;
  DH_get0_pqg(dh, &p, &q, &g);
  DH_set0_pqg(new_dh, BN_dup(p), q ? BN_dup(q) : nullptr, BN_dup(g));
  DH_set0_key(new_dh, pub, priv);

  EVP_PKEY_free(_pkey);
  _pkey = EVP_PKEY_new();
  EVP_PKEY_assign_DH(_pkey, new_dh);
}

void HybridDiffieHellman::ensureInitialized() {
  if (!_pkey)
    throw std::runtime_error("DiffieHellman not initialized");
}

#pragma clang diagnostic pop
} // namespace margelo::nitro::crypto
