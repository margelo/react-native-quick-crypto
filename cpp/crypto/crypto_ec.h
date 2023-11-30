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

namespace margelo {
namespace jsi = facebook::jsi;

class ECDH final {
public:
    static ECPointPointer BufferToPoint(jsi::Runtime &rt,
                                        const EC_GROUP* group,
                                        jsi::ArrayBuffer &buf);
};

}


#endif /* crypto_ec_hpp */
