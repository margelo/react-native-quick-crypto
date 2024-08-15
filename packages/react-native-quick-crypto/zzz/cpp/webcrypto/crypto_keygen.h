#ifndef crypto_keygen_h
#define crypto_keygen_h

#include <jsi/jsi.h>

#include "MGLKeys.h"
#ifdef ANDROID
#include "Utils/MGLUtils.h"
#else
#include "MGLUtils.h"
#endif

namespace margelo {

namespace jsi = facebook::jsi;

FieldDefinition GenerateSecretKeyFieldDefinition(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);

struct SecretKeyGenConfig {
  size_t length;  // in bytes
  SecretKeyGenConfig() = default;
};

class SecretKeyGen {
  public:
  bool GetParamsFromJS(jsi::Runtime &rt, const jsi::Value *args);
  bool DoKeyGen();
  std::shared_ptr<KeyObjectHandle> GetHandle();
  private:
  SecretKeyGenConfig params_;
  std::shared_ptr<KeyObjectData> key_;
};

} // namespace margelo

#endif // crypto_keygen_h
