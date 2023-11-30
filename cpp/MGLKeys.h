//
//  MGLCipherKeys.h
//  react-native-quick-crypto
//
//  Created by Oscar on 20.06.22.
//

#ifndef MGLCipherKeys_h
#define MGLCipherKeys_h

#include <jsi/jsi.h>
#include <openssl/evp.h>

#include <memory>
#include <optional>
#include <string>

#ifdef ANDROID
#include "Utils/MGLUtils.h"
#else
#include "MGLUtils.h"
#include "JSIUtils/MGLSmartHostObject.h"
#endif

// This file should roughly match https://github.com/nodejs/node/blob/main/src/crypto/crypto_keys.cc

namespace margelo {

namespace jsi = facebook::jsi;

enum PKEncodingType {
  // RSAPublicKey / RSAPrivateKey according to PKCS#1.
  kKeyEncodingPKCS1,
  // PrivateKeyInfo or EncryptedPrivateKeyInfo according to PKCS#8.
  kKeyEncodingPKCS8,
  // SubjectPublicKeyInfo according to X.509.
  kKeyEncodingSPKI,
  // ECPrivateKey according to SEC1.
  kKeyEncodingSEC1
};

enum PKFormatType { kKeyFormatDER, kKeyFormatPEM, kKeyFormatJWK };

enum KeyType { kKeyTypeSecret, kKeyTypePublic, kKeyTypePrivate };

enum KeyEncodingContext {
  kKeyContextInput,
  kKeyContextExport,
  kKeyContextGenerate
};

enum class ParseKeyResult {
  kParseKeyOk,
  kParseKeyNotRecognized,
  kParseKeyNeedPassphrase,
  kParseKeyFailed
};

struct AsymmetricKeyEncodingConfig {
  bool output_key_object_ = false;
  PKFormatType format_ = kKeyFormatDER;
  std::optional<PKEncodingType> type_ = std::nullopt;
};

using PublicKeyEncodingConfig = AsymmetricKeyEncodingConfig;

struct PrivateKeyEncodingConfig : public AsymmetricKeyEncodingConfig {
  const EVP_CIPHER *cipher_;
  // The ByteSource alone is not enough to distinguish between "no passphrase"
  // and a zero-length passphrase (which can be a null pointer), therefore, we
  // use a NonCopyableMaybe.
  NonCopyableMaybe<ByteSource> passphrase_;
};

// Here node uses extends MemoryRetainer no clue what that is, something with
// Snapshots stripped it for our implementation but if something doesn't work,
// you know why
class ManagedEVPPKey {
 public:
  ManagedEVPPKey() {}
  explicit ManagedEVPPKey(EVPKeyPointer &&pkey);
  ManagedEVPPKey(const ManagedEVPPKey &that);
  ManagedEVPPKey &operator=(const ManagedEVPPKey &that);

  operator bool() const;
  EVP_PKEY *get() const;

  static PublicKeyEncodingConfig GetPublicKeyEncodingFromJs(
      jsi::Runtime &runtime, const jsi::Value *arguments, unsigned int *offset,
      KeyEncodingContext context);

  static NonCopyableMaybe<PrivateKeyEncodingConfig> GetPrivateKeyEncodingFromJs(
      jsi::Runtime &runtime, const jsi::Value *arguments, unsigned int *offset,
      KeyEncodingContext context);
  //
  static ManagedEVPPKey GetParsedKey(jsi::Runtime &runtime,
                                     EVPKeyPointer &&pkey, ParseKeyResult ret,
                                     const char *default_msg);

  static ManagedEVPPKey GetPublicOrPrivateKeyFromJs(jsi::Runtime &runtime,
                                                    const jsi::Value *args,
                                                    unsigned int *offset);

  static ManagedEVPPKey GetPrivateKeyFromJs(jsi::Runtime &runtime,
                                            const jsi::Value *args,
                                            unsigned int *offset,
                                            bool allow_key_object);

  static std::optional<StringOrBuffer> ToEncodedPublicKey(
      jsi::Runtime &runtime, ManagedEVPPKey key,
      const PublicKeyEncodingConfig &config);

  static std::optional<StringOrBuffer> ToEncodedPrivateKey(
      jsi::Runtime &runtime, ManagedEVPPKey key,
      const PrivateKeyEncodingConfig &config);

 private:
  //  size_t size_of_private_key() const;
  //  size_t size_of_public_key() const;

  EVPKeyPointer pkey_;
};

class JSI_EXPORT KeyObjectHandle: public jsi::HostObject {
public:
    KeyObjectHandle() {};
    
    jsi::Value get(jsi::Runtime &rt, const jsi::PropNameID &propNameID);
};

}  // namespace margelo

#endif /* MGLCipherKeys_h */
