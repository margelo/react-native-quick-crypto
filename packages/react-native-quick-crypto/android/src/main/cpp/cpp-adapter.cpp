#include <jni.h>

#include "random/HybridRandom.hpp"
#include <NitroModules/HybridObjectRegistry.hpp>

using namespace margelo::nitro::crypto;
using namespace margelo::crypto;

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
  HybridObjectRegistry::registerHybridObjectConstructor(
    "Random", []() -> std::shared_ptr<HybridObject> { return std::make_shared<HybridRandom>();
  });

  return JNI_VERSION_1_2;
}
