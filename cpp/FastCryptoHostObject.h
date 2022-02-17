#ifndef FASTCRYPTOHOSTOBJECT_H
#define FASTCRYPTOHOSTOBJECT_H

#include <jsi/jsi.h>

namespace margelo {

using namespace facebook;

class JSI_EXPORT FastCryptoHostObject: public jsi::HostObject {
public:
  explicit FastCryptoHostObject() {}

public:
  jsi::Value get(jsi::Runtime&, const jsi::PropNameID& name) override;
  std::vector<jsi::PropNameID> getPropertyNames(jsi::Runtime& rt) override;
};

} // namespace margelo

#endif /* FASTCRYPTOHOSTOBJECT_H */
