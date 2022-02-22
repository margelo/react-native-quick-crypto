#ifndef JSICRYPTOHOSTOBJECT_H
#define JSICRYPTOHOSTOBJECT_H

#include <jsi/jsi.h>

namespace margelo {

using namespace facebook;

class JSI_EXPORT JSICryptoHostObject: public jsi::HostObject {
public:
  explicit JSICryptoHostObject() {}

public:
  jsi::Value get(jsi::Runtime&, const jsi::PropNameID& name) override;
  std::vector<jsi::PropNameID> getPropertyNames(jsi::Runtime& rt) override;
};

} // namespace margelo

#endif /* JSICRYPTOHOSTOBJECT_H */
