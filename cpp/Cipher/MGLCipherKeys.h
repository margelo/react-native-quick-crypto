//
//  MGLCipherKeys.hpp
//  react-native-fast-crypto
//
//  Created by Oscar on 20.06.22.
//

#ifndef MGLCipherKeys_hpp
#define MGLCipherKeys_hpp

#include <jsi/jsi.h>
#include <openssl/evp.h>

#include <memory>
#include <optional>
#include <string>

#ifdef ANDROID
#include "JSIUtils/MGLUtils.h"
#else
#include "MGLUtils.h"
#endif

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
  const EVP_CIPHER* cipher_;
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
  explicit ManagedEVPPKey(EVPKeyPointer&& pkey);
  ManagedEVPPKey(const ManagedEVPPKey& that);
  ManagedEVPPKey& operator=(const ManagedEVPPKey& that);

  operator bool() const;
  EVP_PKEY* get() const;

  //  static PublicKeyEncodingConfig GetPublicKeyEncodingFromJs(
  //                                                            const
  //                                                            v8::FunctionCallbackInfo<v8::Value>&
  //                                                            args, unsigned
  //                                                            int* offset,
  //                                                            KeyEncodingContext
  //                                                            context);
  //
  static NonCopyableMaybe<PrivateKeyEncodingConfig> GetPrivateKeyEncodingFromJs(
      jsi::Runtime& runtime, const jsi::Value* arguments, unsigned int* offset,
      KeyEncodingContext context);
  //
  static ManagedEVPPKey GetParsedKey(jsi::Runtime& runtime,
                                     EVPKeyPointer&& pkey, ParseKeyResult ret,
                                     const char* default_msg);

  static ManagedEVPPKey GetPublicOrPrivateKeyFromJs(jsi::Runtime& runtime,
                                                    const jsi::Value* args,
                                                    unsigned int* offset);

  //  static ManagedEVPPKey GetPrivateKeyFromJs(
  //                                            const
  //                                            v8::FunctionCallbackInfo<v8::Value>&
  //                                            args, unsigned int* offset, bool
  //                                            allow_key_object);
  //
  //  static v8::Maybe<bool> ToEncodedPublicKey(
  //                                            Environment* env,
  //                                            ManagedEVPPKey key,
  //                                            const PublicKeyEncodingConfig&
  //                                            config, v8::Local<v8::Value>*
  //                                            out);
  //
  //  static v8::Maybe<bool> ToEncodedPrivateKey(
  //                                             Environment* env,
  //                                             ManagedEVPPKey key,
  //                                             const PrivateKeyEncodingConfig&
  //                                             config, v8::Local<v8::Value>*
  //                                             out);

 private:
  size_t size_of_private_key() const;
  size_t size_of_public_key() const;

  EVPKeyPointer pkey_;
};

}  // namespace margelo

#endif /* MGLCipherKeys_hpp */
