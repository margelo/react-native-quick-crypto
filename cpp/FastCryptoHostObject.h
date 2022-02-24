#ifndef FASTCRYPTOHOSTOBJECT_H
#define FASTCRYPTOHOSTOBJECT_H

#include <jsi/jsi.h>
#import <ReactCommon/CallInvoker.h>
#include "Utils/DispatchQueue.h"
#include "JSI Utils/SmartHostObject.h"

namespace margelo {

namespace jsi = facebook::jsi;
namespace react = facebook::react;

class JSI_EXPORT FastCryptoHostObject : public SmartHostObject {
public:
explicit FastCryptoHostObject(std::shared_ptr<react::CallInvoker> jsCallInvoker, std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);

jsi::Value get(jsi::Runtime&, const jsi::PropNameID& name) override;
std::vector<jsi::PropNameID> getPropertyNames(jsi::Runtime& rt) override;

virtual void install(std::vector<std::pair<std::string, JSIValueBuilder> > & fields) override;

virtual ~FastCryptoHostObject() {
}
};

} // namespace margelo

#endif /* FASTCRYPTOHOSTOBJECT_H */
