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
#include "webcrypto/crypto_ec.h"
#include "Utils/MGLUtils.h"
#else
#include "MGLUtils.h"
#include "MGLJSIMacros.h"
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
        JSVariant jsv = JSVariant(std::move(out));
        return toJSI(rt, jsv);
    });

    obj.setProperty(rt,
                    "createKeyObjectHandle",
                    std::move(createKeyObjectHandle));
    obj.setProperty(rt, "ecExportKey", std::move(ecExportKey));
    return obj;
};

}  // namespace margelo

