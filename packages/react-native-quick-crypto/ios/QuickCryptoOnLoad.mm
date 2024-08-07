
#include "HybridRandom.hpp"
#include <NitroModules/HybridObjectRegistry.hpp>

@interface QuickCryptoOnLoad : NSObject
@end

@implementation QuickCryptoOnLoad

using namespace margelo::nitro;
using namespace margelo::crypto;

+ (void)load {
  HybridObjectRegistry::registerHybridObjectConstructor("Random",
                                                        []() -> std::shared_ptr<HybridObject> { return std::make_shared<HybridRandom>(); });
}

@end
