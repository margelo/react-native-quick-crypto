//
//  MGLX25519.cpp
//  react-native-quick-crypto
//
//  Created by Samuel on 22.06.22.
//

#include "MGLX25519.h"

namespace margelo {

namespace jsi = facebook::jsi;

X25519KeyPairGenConfig prepareX25519KeyGenConfig(jsi::Runtime& runtime,
                                                 const jsi::Value* arguments) {
  X25519KeyPairGenConfig config;
  unsigned int offset = 0;

  config.variant = static_cast<KeyVariant>((int)arguments[offset].asNumber());
  offset++;

  config.public_key_encoding = ManagedEVPPKey::GetPublicKeyEncodingFromJs(
      runtime, arguments, &offset, kKeyContextGenerate);

  auto private_key_encoding = ManagedEVPPKey::GetPrivateKeyEncodingFromJs(
      runtime, arguments, &offset, kKeyContextGenerate);

  if (!private_key_encoding.IsEmpty()) {
    config.private_key_encoding = private_key_encoding.Release();
  }

  return config;
}

EVPKeyCtxPointer setupX25519(std::shared_ptr<X25519KeyPairGenConfig> config) {
  EVPKeyCtxPointer ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr));

  if (!ctx) {
    return nullptr;
  }

  if (!EVP_PKEY_keygen_init(ctx.get())) {
    return nullptr;
  }

  return ctx;
}

std::pair<StringOrBuffer, StringOrBuffer> generateX25519KeyPair(
    jsi::Runtime& runtime, std::shared_ptr<X25519KeyPairGenConfig> config) {
  CheckEntropy();

  EVPKeyCtxPointer ctx = setupX25519(config);

  if (!ctx) {
    throw new jsi::JSError(runtime, "Error on key generation job");
  }

  EVP_PKEY* pkey = nullptr;
  if (!EVP_PKEY_keygen(ctx.get(), &pkey)) {
    throw new jsi::JSError(runtime, "Error generating key");
  }

  config->key = ManagedEVPPKey(EVPKeyPointer(pkey));

  std::optional<StringOrBuffer> publicBuffer =
      ManagedEVPPKey::ToEncodedPublicKey(runtime, std::move(config->key),
                                         config->public_key_encoding);
  std::optional<StringOrBuffer> privateBuffer =
      ManagedEVPPKey::ToEncodedPrivateKey(runtime, std::move(config->key),
                                          config->private_key_encoding);

  if (!publicBuffer.has_value() || !privateBuffer.has_value()) {
    throw jsi::JSError(runtime, "Failed to encode public and/or private key");
  }

  return std::make_pair(publicBuffer.value(), privateBuffer.value());
}

}  // namespace margelo
