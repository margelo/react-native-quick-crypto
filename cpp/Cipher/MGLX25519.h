//
//  MGLX25519.h
//  react-native-quick-crypto
//
//  Created by Samuel on 22.06.22.
//

#ifndef REACT_NATIVE_QUICK_CRYPTO_MGLX25519_H
#define REACT_NATIVE_QUICK_CRYPTO_MGLX25519_H

#include <jsi/jsi.h>

#include <memory>
#include <optional>
#include <utility>

#include "MGLKeys.h"
#ifdef ANDROID
#include "Utils/MGLUtils.h"
#else
#include "MGLUtils.h"
#endif

namespace margelo {

namespace jsi = facebook::jsi;

struct X25519KeyPairGenConfig {
  PublicKeyEncodingConfig public_key_encoding;
  PrivateKeyEncodingConfig private_key_encoding;
  ManagedEVPPKey key;

  KeyVariant variant;
};

X25519KeyPairGenConfig prepareX25519KeyGenConfig(jsi::Runtime& runtime,
                                                 const jsi::Value* arguments);

std::pair<StringOrBuffer, StringOrBuffer> generateX25519KeyPair(
    jsi::Runtime& runtime, std::shared_ptr<X25519KeyPairGenConfig> config);

}  // namespace margelo

#endif  // REACT_NATIVE_QUICK_CRYPTO_MGLX25519_H
