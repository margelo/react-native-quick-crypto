#include <jni.h>
#include <jsi/jsi.h>
#include "FastCryptoHostObject.h"

using namespace facebook;

void install(jsi::Runtime& runtime) {
    auto hostObject = std::make_shared<margelo::FastCryptoHostObject>();
    auto object = jsi::Object::createFromHostObject(runtime, hostObject);
    runtime.global().setProperty(runtime, "__FastCryptoProxy", std::move(object));
}

extern "C"
JNIEXPORT void JNICALL
Java_com_reactnativefastcrypto_FastCryptoModule_nativeInstall(JNIEnv *env, jobject clazz, jlong jsiPtr) {
    auto runtime = reinterpret_cast<jsi::Runtime*>(jsiPtr);
    if (runtime) {
        install(*runtime);
    }
    // if runtime was nullptr, FastCrypto will not be installed. This should only happen while Remote Debugging (Chrome), but will be weird either way.
}
