#import <React/RCTBridge+Private.h>
#import <React/RCTUtils.h>
#import <ReactCommon/RCTTurboModule.h>
#import <jsi/jsi.h>
#import "RNTQuickCryptoCxx.h"
#import <ReactCommon/CxxTurboModuleUtils.h>


@interface QuickCryptoModule: NSObject

@end

@implementation QuickCryptoModule

+ (void)load {
    facebook::react::registerCxxModuleToGlobalModuleMap(
                                                        std::string(facebook::react::margelo::RNTQuickCryptoCxx::kModuleName),
                                                        [&](std::shared_ptr<facebook::react::CallInvoker> jsInvoker) {
                                                            return std::make_shared<facebook::react::margelo::RNTQuickCryptoCxx>(jsInvoker);
                                                        });
}

@end
