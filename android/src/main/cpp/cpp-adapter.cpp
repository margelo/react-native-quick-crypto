#include <ReactCommon/CallInvokerHolder.h>
#include <fbjni/fbjni.h>
#include <jni.h>
#include <jsi/jsi.h>

#include "MGLQuickCryptoHostObject.h"

using namespace facebook;

class CryptoCppAdapter : public jni::HybridClass<CryptoCppAdapter> {
 public:
  static auto constexpr kJavaDescriptor =
      "Lcom/reactnativequickcrypto/QuickCryptoModule;";

  static jni::local_ref<jni::HybridClass<CryptoCppAdapter>::jhybriddata>
  initHybrid(jni::alias_ref<jhybridobject> jThis) {
    return makeCxxInstance();
  }

  CryptoCppAdapter() {}

  void install(jsi::Runtime &runtime,
               std::shared_ptr<facebook::react::CallInvoker> jsCallInvoker) {
    auto workerQueue = std::make_shared<margelo::DispatchQueue::dispatch_queue>(
        "margelo crypto worker thread");
    auto hostObject = std::make_shared<margelo::MGLQuickCryptoHostObject>(
        jsCallInvoker, workerQueue);
    auto object = jsi::Object::createFromHostObject(runtime, hostObject);
    runtime.global().setProperty(runtime, "__QuickCryptoProxy",
                                 std::move(object));
  }

  void nativeInstall(
      jlong jsiPtr,
      jni::alias_ref<facebook::react::CallInvokerHolder::javaobject>
          jsCallInvokerHolder) {
    auto jsCallInvoker = jsCallInvokerHolder->cthis()->getCallInvoker();
    auto runtime = reinterpret_cast<jsi::Runtime *>(jsiPtr);
    if (runtime) {
      install(*runtime, jsCallInvoker);
    }
    // if runtime was nullptr, QuickCrypto will not be installed. This should
    // only happen while Remote Debugging (Chrome), but will be weird either
    // way.
  }

  static void registerNatives() {
    registerHybrid(
        {makeNativeMethod("initHybrid", CryptoCppAdapter::initHybrid),
         makeNativeMethod("nativeInstall", CryptoCppAdapter::nativeInstall)});
  }

 private:
  friend HybridBase;
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *) {
  return facebook::jni::initialize(vm,
                                   [] { CryptoCppAdapter::registerNatives(); });
}
