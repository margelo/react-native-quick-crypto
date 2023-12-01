//
//  MGLWebCrypto.cpp
//  react-native-quick-crypto
//
//  Created by Oscar Franco on 1/12/23.
//

#include "MGLWebCrypto.h"

#include <memory>
#include <utility>
#include "MGLJSIMacros.h"
#include "MGLKeys.h"
#include "crypto_ec.h"

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
        std::shared_ptr<KeyObjectHandle> handle = std::static_pointer_cast<KeyObjectHandle>(args[1].asObject(rt).getHostObject(rt));
        std::shared_ptr<KeyObjectData> key_data = handle->data_;
        ECDH::doExport(rt, static_cast<WebCryptoKeyFormat>(args[0].asNumber()), key_data, &out);
        auto buffer = ByteSourceToArrayBuffer(rt, out);
        return buffer;
    });
    
    obj.setProperty(rt, "createKeyObjectHandle", std::move(createKeyObjectHandle));
    obj.setProperty(rt, "ecExportKey", std::move(ecExportKey));
    return obj;
};

}  // namespace margelo

