//
//  crypto_ec.hpp
//  BEMCheckBox
//
//  Created by Oscar Franco on 30/11/23.
//

#ifndef crypto_ec_hpp
#define crypto_ec_hpp

#import <jsi/jsi.h>

namespace margelo {
namespace jsi = facebook::jsi;

class ECDH final {
    static ECPointPointer BufferToPoint(const EC_GROUP* group,
                                          jsi::ArrayBuffer buf);
}


}


#endif /* crypto_ec_hpp */
