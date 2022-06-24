//
//  MGLRsa.cpp
//  react-native-quick-crypto
//
//  Created by Oscar on 22.06.22.
//

#include "MGLRsa.h"

#include <utility>

namespace margelo {

namespace jsi = facebook::jsi;

EVPKeyCtxPointer setup(RsaKeyPairGenConfig* params) {
  EVPKeyCtxPointer ctx(EVP_PKEY_CTX_new_id(
      params->variant == kKeyVariantRSA_PSS ? EVP_PKEY_RSA_PSS : EVP_PKEY_RSA,
      nullptr));

  if (EVP_PKEY_keygen_init(ctx.get()) <= 0) return EVPKeyCtxPointer();

  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), params->modulus_bits) <= 0) {
    return EVPKeyCtxPointer();
  }

  // 0x10001 is the default RSA exponent.
  if (params->exponent != 0x10001) {
    BignumPointer bn(BN_new());
    //    CHECK_NOT_NULL(bn.get());
    BN_set_word(bn.get(), params->exponent);
    // EVP_CTX accepts ownership of bn on success.
    if (EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx.get(), bn.get()) <= 0) {
      return EVPKeyCtxPointer();
    }

    bn.release();
  }

  if (params->variant == kKeyVariantRSA_PSS) {
    if (params->md != nullptr &&
        EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx.get(), params->md) <= 0) {
      return EVPKeyCtxPointer();
    }

    // TODO(tniessen): This appears to only be necessary in OpenSSL 3, while
    // OpenSSL 1.1.1 behaves as recommended by RFC 8017 and defaults the MGF1
    // hash algorithm to the RSA-PSS hashAlgorithm. Remove this code if the
    // behavior of OpenSSL 3 changes.
    const EVP_MD* mgf1_md = params->mgf1_md;
    if (mgf1_md == nullptr && params->md != nullptr) {
      mgf1_md = params->md;
    }

    if (mgf1_md != nullptr &&
        EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(ctx.get(), mgf1_md) <= 0) {
      return EVPKeyCtxPointer();
    }

    int saltlen = params->saltlen;
    if (saltlen < 0 && params->md != nullptr) {
      saltlen = EVP_MD_size(params->md);
    }

    if (saltlen >= 0 &&
        EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx.get(), saltlen) <= 0) {
      return EVPKeyCtxPointer();
    }
  }

  return ctx;
}

jsi::Value generateRSAKeyPair(jsi::Runtime& runtime,
                              const jsi::Value* arguments) {
  RsaKeyPairGenConfig config = RsaKeyPairGenConfig();

  // This is a funky one: depending on which encryption scheme you are
  // using, there is a variable number of arguments that will need to be
  // parsed, therefore this pointer will be used by the internal functions
  // as they go reading the arguments based on the selected scheme. I
  // tried to keep as close to the node implementation to make future
  // debugging easier
  unsigned int offset = 1;

  // TODO(osp)
  //    CHECK(args[*offset]->IsUint32());  // Variant
  //    CHECK(args[*offset + 1]->IsUint32());  // Modulus bits
  //    CHECK(args[*offset + 2]->IsUint32());  // Exponent
  config.variant =
      static_cast<RSAKeyVariant>((int)arguments[offset].asNumber());

  // TODO(osp)
  //    CHECK_IMPLIES(params->params.variant != kKeyVariantRSA_PSS,
  //                  args.Length() == 10);
  //    CHECK_IMPLIES(params->params.variant == kKeyVariantRSA_PSS,
  //                  args.Length() == 13);
  config.modulus_bits =
      static_cast<unsigned int>(arguments[offset + 1].asNumber());
  config.exponent = static_cast<unsigned int>(arguments[offset + 2].asNumber());

  offset += 3;

  if (config.variant == kKeyVariantRSA_PSS) {
    if (!arguments[offset].isUndefined()) {
      // TODO(osp) CHECK(string)
      config.md = EVP_get_digestbyname(
          arguments[offset].asString(runtime).utf8(runtime).c_str());

      if (config.md == nullptr) {
        jsi::detail::throwJSError(runtime, "invalid digest");
        throw new jsi::JSError(runtime, "invalid digest");
      }
    }

    if (!arguments[offset + 1].isUndefined()) {
      // TODO(osp) CHECK(string)
      config.mgf1_md = EVP_get_digestbyname(
          arguments[offset + 1].asString(runtime).utf8(runtime).c_str());

      if (config.mgf1_md == nullptr) {
        jsi::detail::throwJSError(runtime, "invalid digest");
        throw new jsi::JSError(runtime, "invalid digest");
      }
    }

    if (!arguments[offset + 2].isUndefined()) {
      //        CHECK(args[*offset + 2]->IsInt32());
      config.saltlen = static_cast<int>(arguments[offset + 2].asNumber());

      if (config.saltlen < 0) {
        jsi::detail::throwJSError(runtime, "salt length is out of range");
        throw new jsi::JSError(runtime, "salt length is out of range");
      }
    }

    offset += 3;
  }

  config.public_key_encoding = ManagedEVPPKey::GetPublicKeyEncodingFromJs(
      runtime, arguments, &offset, kKeyContextGenerate);

  auto private_key_encoding = ManagedEVPPKey::GetPrivateKeyEncodingFromJs(
      runtime, arguments, &offset, kKeyContextGenerate);

  if (!private_key_encoding.IsEmpty()) {
    config.private_key_encoding = private_key_encoding.Release();
  }

  CheckEntropy();

  EVPKeyCtxPointer ctx = setup(&config);

  if (!ctx) {
    jsi::detail::throwJSError(runtime, "Error on key generation job");
    throw new jsi::JSError(runtime, "Error on key generation job");
  }

  // Generate the key
  EVP_PKEY* pkey = nullptr;
  if (!EVP_PKEY_keygen(ctx.get(), &pkey)) {
    jsi::detail::throwJSError(runtime, "Error generating key");
    throw new jsi::JSError(runtime, "Error generating key");
  }

  config.key = ManagedEVPPKey(EVPKeyPointer(pkey));

  std::optional<jsi::Value> publicBuffer = ManagedEVPPKey::ToEncodedPublicKey(
      runtime, std::move(config.key), config.public_key_encoding);
  std::optional<jsi::Value> privateBuffer = ManagedEVPPKey::ToEncodedPrivateKey(
      runtime, std::move(config.key), config.private_key_encoding);

  if (!publicBuffer.has_value() || !privateBuffer.has_value()) {
    jsi::detail::throwJSError(runtime,
                              "Failed to encode public and/or private key");
  }

  return jsi::Array::createWithElements(runtime, jsi::Value::undefined(),
                                        publicBuffer.value(),
                                        privateBuffer.value());
}

}  // namespace margelo
