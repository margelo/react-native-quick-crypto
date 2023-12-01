//
//  MGLWebCrypto.hpp
//  react-native-quick-crypto
//
//  Created by Oscar Franco on 1/12/23.
//

#ifndef MGLWebCryptoHostObject_h
#define MGLWebCryptoHostObject_h

#include <memory>
#include <jsi/jsi.h>
#ifdef ANDROID
#include "JSIUtils/MGLSmartHostObject.h"
#else
#include "MGLSmartHostObject.h"
#endif

namespace margelo {
namespace jsi = facebook::jsi;

jsi::Value createWebCryptoObject(jsi::Runtime &rt);

}  // namespace margelo

#endif /* MGLWebCrypto_hpp */
