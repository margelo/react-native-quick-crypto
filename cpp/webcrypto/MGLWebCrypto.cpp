//
//  MGLWebCrypto.cpp
//  react-native-quick-crypto
//
//  Created by Oscar Franco on 1/12/23.
//

#include "MGLWebCrypto.h"

#include <memory>
#include <utility>
#include "MGLKeys.h"

#ifdef ANDROID
#include "JSIUtils/MGLJSIMacros.h"
#include "Sig/MGLSignHostObjects.h"
#include "Utils/MGLUtils.h"
#include "webcrypto/crypto_ec.h"
#else
#include "MGLJSIMacros.h"
#include "MGLSignHostObjects.h"
#include "MGLUtils.h"
#include "crypto_ec.h"
#endif

namespace margelo {
namespace jsi = facebook::jsi;
namespace react = facebook::react;

jsi::Value createWebCryptoObject(jsi::Runtime &rt) {
    auto obj = jsi::Object(rt);

    auto createKeyObjectHandle = HOSTFN("createKeyObjectHandle", 0) {
        auto keyObjectHandleHostObject =
                std::make_shared<KeyObjectHandle>();
        return jsi::Object::createFromHostObject(rt, keyObjectHandleHostObject);
    });

    auto ecExportKey = HOSTFN("ecExportKey", 2) {
        ByteSource out;
        std::shared_ptr<KeyObjectHandle> handle =
            std::static_pointer_cast<KeyObjectHandle>(
                args[1].asObject(rt).getHostObject(rt));
        std::shared_ptr<KeyObjectData> key_data = handle->Data();
        WebCryptoKeyExportStatus status = ECDH::doExport(rt,
                                                         key_data,
                                                         static_cast<WebCryptoKeyFormat>(args[0].asNumber()),
                                                         {}, // blank params
                                                         &out);
        if (status != WebCryptoKeyExportStatus::OK) {
            throw jsi::JSError(rt, "error exporting key, status: " + std::to_string(static_cast<int>(status)));
        }
        return toJSI(rt, std::move(out));
    });

    auto signVerify = HOSTFN("signVerify", 4) {
      auto ssv = SubtleSignVerify();
      auto params = ssv.GetParamsFromJS(rt, args);
      ByteSource out;
      ssv.DoSignVerify(rt, params, out);
      return ssv.EncodeOutput(rt, params, out);
    });

    obj.setProperty(rt,
                    "createKeyObjectHandle",
                    std::move(createKeyObjectHandle));
    obj.setProperty(rt, "ecExportKey", std::move(ecExportKey));
    obj.setProperty(rt, "signVerify", std::move(signVerify));
    return obj;
};

}  // namespace margelo

