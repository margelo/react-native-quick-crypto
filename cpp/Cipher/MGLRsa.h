//
//  MGLRsa.hpp
//  react-native-quick-crypto
//
//  Created by Oscar on 22.06.22.
//

#ifndef MGLRsa_hpp
#define MGLRsa_hpp

#include <optional>

#include "MGLUtils.h"

namespace margelo {

enum RSAKeyVariant {
  kKeyVariantRSA_SSA_PKCS1_v1_5,
  kKeyVariantRSA_PSS,
  kKeyVariantRSA_OAEP
};

// struct RsaKeyPairParams final {
//   RSAKeyVariant variant;
//   unsigned int modulus_bits;
//   unsigned int exponent;
//
//   // The following options are used for RSA-PSS. If any of them are set, a
//   // RSASSA-PSS-params sequence will be added to the key.
//   const EVP_MD* md = nullptr;
//   const EVP_MD* mgf1_md = nullptr;
//   int saltlen = -1;
// };

// using RsaKeyPairGenConfig = KeyPairGenConfig<RsaKeyPairParams>;

// struct RsaKeyGenTraits final {
//   using AdditionalParameters = RsaKeyPairGenConfig;
//   static constexpr const char* JobName = "RsaKeyPairGenJob";
//
//   static EVPKeyCtxPointer Setup(RsaKeyPairGenConfig* params);
//
//   //  static V8::Maybe<bool> AdditionalConfig(
//   //                                          CryptoJobMode mode,
//   //                                          const
//   // v8::FunctionCallbackInfo<v8::Value>&
//   //                                          args, unsigned int* offset,
//   //                                          RsaKeyPairGenConfig* params);
// };
//
// using RSAKeyPairGenJob = KeyGenJob<KeyPairGenTraits<RsaKeyGenTraits>>;
//
// struct RSAKeyExportConfig final {
//   RSAKeyVariant variant = kKeyVariantRSA_SSA_PKCS1_v1_5;
// };
//
// struct RSAKeyExportTraits final {
//   static constexpr const char* JobName = "RSAKeyExportJob";
//   using AdditionalParameters = RSAKeyExportConfig;
//
//   //  static v8::Maybe<bool> AdditionalConfig(
//   //                                          const
//   // v8::FunctionCallbackInfo<v8::Value>&
//   //                                          args, unsigned int offset,
//   //                                          RSAKeyExportConfig* config);
//
//   //  static WebCryptoKeyExportStatus DoExport(
//   //                                           std::shared_ptr<KeyObjectData>
//   //                                           key_data, WebCryptoKeyFormat
//   //                                           format, const
//   RSAKeyExportConfig&
//   //                                           params, ByteSource* out);
// };
//
// using RSAKeyExportJob = KeyExportJob<RSAKeyExportTraits>;
//
// struct RSACipherConfig final {
//   CryptoJobMode mode;
//   ByteSource label;
//   int padding = 0;
//   const EVP_MD* digest = nullptr;
//
//   RSACipherConfig() = default;
//
//   RSACipherConfig(RSACipherConfig&& other) noexcept;
// };
//
// struct RSACipherTraits final {
//   static constexpr const char* JobName = "RSACipherJob";
//   using AdditionalParameters = RSACipherConfig;
//
//   //  static v8::Maybe<bool> AdditionalConfig(
//   //                                          CryptoJobMode mode,
//   //                                          const
//   // v8::FunctionCallbackInfo<v8::Value>&
//   //                                          args, unsigned int offset,
//   //                                          WebCryptoCipherMode
//   cipher_mode,
//   //                                          RSACipherConfig* config);
//
//   //  static WebCryptoCipherStatus DoCipher(
//   //                                        Environment* env,
//   //                                        std::shared_ptr<KeyObjectData>
//   //                                        key_data, WebCryptoCipherMode
//   //                                        cipher_mode, const
//   RSACipherConfig&
//   //                                        params, const ByteSource& in,
//   //                                        ByteSource* out);
// };
//
// using RSACipherJob = CipherJob<RSACipherTraits>;

// v8::Maybe<bool> ExportJWKRsaKey(
//                                 Environment* env,
//                                 std::shared_ptr<KeyObjectData> key,
//                                 v8::Local<v8::Object> target);
//
// std::shared_ptr<KeyObjectData> ImportJWKRsaKey(
//                                                Environment* env,
//                                                v8::Local<v8::Object> jwk,
//                                                const
//                                                v8::FunctionCallbackInfo<v8::Value>&
//                                                args, unsigned int offset);
//
// v8::Maybe<bool> GetRsaKeyDetail(
//                                 Environment* env,
//                                 std::shared_ptr<KeyObjectData> key,
//                                 v8::Local<v8::Object> target);

// namespace RSAAlg {
// void Initialize(Environment* env, v8::Local<v8::Object> target);
// void RegisterExternalReferences(ExternalReferenceRegistry* registry);
// }  // namespace RSAAlg

}  // namespace margelo

#endif /* MGLRsa_hpp */
