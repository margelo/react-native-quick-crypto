#ifndef FASTCRYPTOHOSTOBJECT_H
#define FASTCRYPTOHOSTOBJECT_H

#include <jsi/jsi.h>
#import <ReactCommon/CallInvoker.h>
#include "Utils/DispatchQueue.h"

namespace margelo {

namespace jsi = facebook::jsi;
namespace react = facebook::react;

class JSI_EXPORT FastCryptoHostObject : public jsi::HostObject {
public:
explicit FastCryptoHostObject(std::shared_ptr<react::CallInvoker> jsCallInvoker) :
  weakJsCallInvoker(jsCallInvoker), dispatchQueue("crypto dispatcher", 1)
{
}

jsi::Value get(jsi::Runtime&, const jsi::PropNameID& name) override;
std::vector<jsi::PropNameID> getPropertyNames(jsi::Runtime& rt) override;

void runOnWorkerThread(std::function<void(void)> && job);
void runOnJSThread(std::function<void(void)> && job);

private:
std::weak_ptr<react::CallInvoker> weakJsCallInvoker;
DispatchQueue::dispatch_queue dispatchQueue;
};

} // namespace margelo

#endif /* FASTCRYPTOHOSTOBJECT_H */
