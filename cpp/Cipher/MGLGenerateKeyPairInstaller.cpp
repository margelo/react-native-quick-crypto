//
//  MGLGenerateKeyPairInstaller.cpp
//  react-native-quick-crypto
//
//  Created by Oscar on 22.06.22.
//

#include "MGLGenerateKeyPairInstaller.h"

#include <iostream>
#include <memory>

#ifdef ANDROID
#include "JSIUtils/MGLJSIMacros.h"
#else
#include "MGLJSIMacros.h"
#endif
#include "MGLCipherKeys.h"
#include "MGLRsa.h"

using namespace facebook;

namespace margelo {

FieldDefinition getGenerateKeyPairFieldDefinition(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue) {
  return HOST_LAMBDA("generateKeyPair", {
    bool isAsync = arguments[0].getBool();

    // This is a funky one: depending on which encryption scheme you are using,
    // there is a variable number of arguments that will need to be parsed,
    // therefore this pointer will be used by the internal functions as they go
    // reading the arguments based on the selected scheme Tried to keep as close
    // to the node implementation to make future debugging easier
    unsigned int offset = 1;

    // TODO(osp)
    //    CHECK(args[*offset]->IsUint32());  // Variant
    //    CHECK(args[*offset + 1]->IsUint32());  // Modulus bits
    //    CHECK(args[*offset + 2]->IsUint32());  // Exponent
    RSAKeyVariant variant =
        static_cast<RSAKeyVariant>((int)arguments[offset].asNumber());

    // TODO(osp)
    //    CHECK_IMPLIES(params->params.variant != kKeyVariantRSA_PSS,
    //                  args.Length() == 10);
    //    CHECK_IMPLIES(params->params.variant == kKeyVariantRSA_PSS,
    //                  args.Length() == 13);
    unsigned int modulus_bits =
        static_cast<unsigned int>(arguments[offset + 1].asNumber());
    unsigned int exponent =
        static_cast<unsigned int>(arguments[offset + 2].asNumber());

    offset += 3;

    const EVP_MD* md = nullptr;
    const EVP_MD* mgf1_md = nullptr;
    int saltlen = -1;

    if (variant == kKeyVariantRSA_PSS) {
      if (!arguments[offset].isUndefined()) {
        // TODO(osp) CHECK(string)
        md = EVP_get_digestbyname(
            arguments[offset].asString(runtime).utf8(runtime).c_str());

        if (md == nullptr) {
          jsi::detail::throwJSError(runtime, "invalid digest");
          throw new jsi::JSError(runtime, "invalid digest");
        }
      }

      if (!arguments[offset + 1].isUndefined()) {
        // TODO(osp) CHECK(string)
        mgf1_md = EVP_get_digestbyname(
            arguments[offset + 1].asString(runtime).utf8(runtime).c_str());

        if (mgf1_md == nullptr) {
          jsi::detail::throwJSError(runtime, "invalid digest");
          throw new jsi::JSError(runtime, "invalid digest");
        }
      }

      if (!arguments[offset + 2].isUndefined()) {
        //        CHECK(args[*offset + 2]->IsInt32());
        saltlen = static_cast<int>(arguments[offset + 2].asNumber());

        if (saltlen < 0) {
          jsi::detail::throwJSError(runtime, "salt length is out of range");
          throw new jsi::JSError(runtime, "salt length is out of range");
        }
      }

      offset += 3;
    }

    auto public_key_encoding = ManagedEVPPKey::GetPublicKeyEncodingFromJs(
        runtime, arguments, &offset, kKeyContextGenerate);

    auto private_key_encoding = ManagedEVPPKey::GetPrivateKeyEncodingFromJs(
        runtime, arguments, &offset, kKeyContextGenerate);

    //    if (!private_key_encoding.IsEmpty())
    //      params->private_key_encoding = private_key_encoding.Release();

    std::cout << "Received variant" << variant << " and isAsync " << isAsync
              << std::endl;
    return {};
  });
}
}  // namespace margelo
