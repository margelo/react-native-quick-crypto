#import "FastCryptoModule.h"

#import <React/RCTBridge+Private.h>
#import <React/RCTUtils.h>
#import <jsi/jsi.h>

#import "FastCryptoHostObject.h"

@implementation FastCryptoModule

RCT_EXPORT_MODULE(FastCrypto)

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(install)
{
    NSLog(@"Installing JSI bindings for react-native-fast-crypto...");
    RCTBridge* bridge = [RCTBridge currentBridge];
    RCTCxxBridge* cxxBridge = (RCTCxxBridge*)bridge;
    if (cxxBridge == nil) {
        return @false;
    }

    using namespace facebook;

    auto jsiRuntime = (jsi::Runtime*) cxxBridge.runtime;
    if (jsiRuntime == nil) {
        return @false;
    }
    auto& runtime = *jsiRuntime;

    auto hostObject = std::make_shared<margelo::FastCryptoHostObject>();
    auto object = jsi::Object::createFromHostObject(runtime, hostObject);
    runtime.global().setProperty(runtime, "__FastCryptoProxy", std::move(object));

    NSLog(@"Successfully installed JSI bindings for react-native-fast-crypto!");
    return @true;
}

@end
