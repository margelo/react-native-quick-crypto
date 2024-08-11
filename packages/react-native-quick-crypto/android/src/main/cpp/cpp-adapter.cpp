#include <fbjni/fbjni.h>
#include <jni.h>

using namespace facebook;

class CryptoCppAdapter : public jni::HybridClass<CryptoCppAdapter> {
public:
  static auto constexpr kJavaDescriptor = "Lcom/margelo/quickcrypto/QuickCryptoModule;";

  static jni::local_ref<jni::HybridClass<CryptoCppAdapter>::jhybriddata> initHybrid(jni::alias_ref<jhybridobject> jThis) {
    return makeCxxInstance();
  }

  CryptoCppAdapter() {}

  static void registerNatives() {
    registerHybrid(
        {makeNativeMethod("initHybrid", CryptoCppAdapter::initHybrid), makeNativeMethod("nativeInstall", CryptoCppAdapter::nativeInstall)});
  }

private:
  friend HybridBase;
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
  return facebook::jni::initialize(vm, [] { CryptoCppAdapter::registerNatives(); });
}
