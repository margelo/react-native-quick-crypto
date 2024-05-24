#include <ReactCommon/CallInvokerHolder.h>
#include <fbjni/fbjni.h>
#include <jni.h>
#include <jsi/jsi.h>

#import <React/RCTUtils.h>
#import <ReactCommon/RCTTurboModule.h>
#import "RNTQuickCryptoCxx.h"
#import <ReactCommon/CxxTurboModuleUtils.h>

using namespace facebook;



JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *) {
  facebook::react::registerCxxModuleToGlobalModuleMap(
                                                        std::string(facebook::react::margelo::RNTQuickCryptoCxx::kModuleName),
                                                        [&](std::shared_ptr<facebook::react::CallInvoker> jsInvoker) {
                                                            return std::make_shared<facebook::react::margelo::RNTQuickCryptoCxx>(jsInvoker);
                                                        });
  return JNI_VERSION_1_6;
}
