#ifndef crypto_keygen_h
#define crypto_keygen_h

#include <jsi/jsi.h>

#include "MGLKeys.h"
#ifdef ANDROID
#include "Utils/MGLUtils.h"
#else
#include "MGLUtils.h"
#endif

namespace margelo
{

  namespace jsi = facebook::jsi;

  struct SecretKeyGenConfig {
    size_t length;  // In bytes.
    ByteSource out; // Placeholder for the generated key bytes.

    SecretKeyGenConfig() = default;
  };

  class SecretKeyGen {
   public:
    static jsi::Value DoKeyGen(jsi::Runtime &rt, const jsi::Value *args);
    static jsi::Value DoKeyGenSync(jsi::Runtime &rt, const jsi::Value *args);
    inline SecretKeyGen(FnMode mode) {
      this->setMode(mode);
    }
   private:
    inline void setMode(FnMode mode) { mode_ = mode; };
    bool getParamsFromJS(jsi::Runtime &rt, const jsi::Value *args);
    bool doKeyGen();
    ByteSource getKey();

    FnMode mode_;
    SecretKeyGenConfig params_;
    ByteSource key_;
  };

} // namespace margelo

#endif // crypto_keygen_h
