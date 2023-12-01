//
//  crypto_ec.hpp
//  BEMCheckBox
//
//  Created by Oscar Franco on 30/11/23.
//

#ifndef crypto_ec_h
#define crypto_ec_h

#include <jsi/jsi.h>
#include <openssl/ec.h>
#include "MGLUtils.h"
#include "MGLWebCrypto.h"
#include "MGLKeys.h"

namespace margelo {
namespace jsi = facebook::jsi;

class ECDH final {
public:
    static ECPointPointer BufferToPoint(jsi::Runtime &rt,
                                        const EC_GROUP* group,
                                        jsi::ArrayBuffer &buf);
    static void doExport(jsi::Runtime &rt, WebCryptoKeyFormat format, std::shared_ptr<KeyObjectData> key_data, ByteSource* out);
};

}


#endif /* crypto_ec_hpp */
