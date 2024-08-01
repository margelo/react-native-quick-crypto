//
//  MGLWebCrypto.hpp
//  react-native-quick-crypto
//
//  Created by Oscar Franco on 1/12/23.
//

#ifndef MGLWebCryptoHostObject_h
#define MGLWebCryptoHostObject_h

#include <jsi/jsi.h>
#include <memory>

#ifdef ANDROID
#include "JSIUtils/MGLSmartHostObject.h"
#else
#include "MGLSmartHostObject.h"
#endif

namespace margelo {
namespace jsi = facebook::jsi;

class MGLWebCryptoHostObject : public MGLSmartHostObject {
 public:
  MGLWebCryptoHostObject(
      std::shared_ptr<react::CallInvoker> jsCallInvoker,
      std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);
};

}  // namespace margelo

#endif /* MGLWebCrypto_hpp */
