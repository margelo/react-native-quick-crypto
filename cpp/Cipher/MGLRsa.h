//
//  MGLRsa.hpp
//  react-native-quick-crypto
//
//  Created by Oscar on 22.06.22.
//

#ifndef MGLRsa_hpp
#define MGLRsa_hpp

#include <jsi/jsi.h>

#include <memory>
#include <optional>
#include <utility>

#include "MGLCipherKeys.h"
#include "MGLUtils.h"

namespace margelo {

namespace jsi = facebook::jsi;

enum RSAKeyVariant {
  kKeyVariantRSA_SSA_PKCS1_v1_5,
  kKeyVariantRSA_PSS,
  kKeyVariantRSA_OAEP
};

// On node there is a complete madness of structs/classes that encapsulate and
// initialize the data in a generic manner this is to be later be used to
// generate the keys in a thread-safe manner (I think) I'm however too dumb and
// after ~4hrs I have given up on trying to replicate/extract the important
// parts For now I'm storing a single config param, a generic abstractino is
// necessary for more schemes. this struct is just a very simplified version
// meant to carry information around
struct RsaKeyPairGenConfig {
  PublicKeyEncodingConfig public_key_encoding;
  PrivateKeyEncodingConfig private_key_encoding;
  ManagedEVPPKey key;

  RSAKeyVariant variant;
  unsigned int modulus_bits;
  unsigned int exponent;

  // The following options are used for RSA-PSS. If any of them are set, a
  // RSASSA-PSS-params sequence will be added to the key.
  const EVP_MD* md = nullptr;
  const EVP_MD* mgf1_md = nullptr;
  int saltlen = -1;
};

RsaKeyPairGenConfig prepareRsaKeyGenConfig(jsi::Runtime& runtime,
                                           const jsi::Value* arguments);

std::pair<StringOrBuffer, StringOrBuffer> generateRSAKeyPair(
    jsi::Runtime& runtime, std::shared_ptr<RsaKeyPairGenConfig> config);

}  // namespace margelo

#endif /* MGLRsa_hpp */
