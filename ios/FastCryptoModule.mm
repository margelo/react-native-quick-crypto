#import "FastCryptoModule.h"

#import <React/RCTBridge+Private.h>
#import <React/RCTUtils.h>
#import <ReactCommon/RCTTurboModule.h>
#import <jsi/jsi.h>

#import "../cpp/FastCryptoHostObject.h"

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
    auto callInvoker = bridge.jsCallInvoker;

    auto hostObject = std::make_shared<margelo::FastCryptoHostObject>(callInvoker);
    auto object = jsi::Object::createFromHostObject(runtime, hostObject);
    runtime.global().setProperty(runtime, "__FastCryptoProxy", std::move(object));

    NSLog(@"Successfully installed JSI bindings for react-native-fast-crypto!");
    return @true;
}

@end
