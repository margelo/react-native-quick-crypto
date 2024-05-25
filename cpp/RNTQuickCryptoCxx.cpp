#include "RNTQuickCryptoCxx.h"
#include "MGLQuickCryptoHostObject.h"
namespace facebook::react {
namespace margelo {


RNTQuickCryptoCxx::RNTQuickCryptoCxx(std::shared_ptr<CallInvoker> jsInvoker): NativeQuickCryptoCxxCxxSpec<RNTQuickCryptoCxx>(std::move(jsInvoker)) {
    
}

double RNTQuickCryptoCxx::install(jsi::Runtime &rt) {
    
    auto workerQueue =
    std::make_shared<::margelo::DispatchQueue::dispatch_queue>("margelo crypto thread");
    auto hostObject = std::static_pointer_cast<jsi::HostObject>(
                                                                std::make_shared<::margelo::MGLQuickCryptoHostObject>(this->jsInvoker_, workerQueue));
    auto object = jsi::Object::createFromHostObject(rt, hostObject);
    rt.global().setProperty(rt, "__QuickCryptoProxy", std::move(object));
    return 1;
}

}

}
