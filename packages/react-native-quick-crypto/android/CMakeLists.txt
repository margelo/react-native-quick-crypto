project(QuickCrypto)
cmake_minimum_required(VERSION 3.10.2)

set(PACKAGE_NAME "QuickCrypto")
set(BUILD_DIR ${CMAKE_SOURCE_DIR}/build)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 17)

# set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g")
# set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")

# Third party libraries (Prefabs)
find_package(fbjni REQUIRED CONFIG)
find_package(ReactAndroid REQUIRED CONFIG)
find_package(openssl REQUIRED CONFIG)
find_library(LOG_LIB log)

add_library(
  ${PACKAGE_NAME}
  SHARED
  "src/main/cpp/cpp-adapter.cpp"
)

target_include_directories(
  ${PACKAGE_NAME}
  PRIVATE
  "../cpp"
  "src/main/cpp"
  "${NODE_MODULES_DIR}/react-native/ReactCommon"
  "${NODE_MODULES_DIR}/react-native/ReactCommon/callinvoker"
  "${NODE_MODULES_DIR}/react-native/ReactAndroid/src/main/jni/react/turbomodule"
  "${NODE_MODULES_DIR}/react-native/ReactCommon/jsi"
  "${NODE_MODULES_DIR}/react-native/ReactCommon/turbomodule/core"
  "${NODE_MODULES_DIR}/react-native/ReactCommon/react/nativemodule/core"
)

#file(GLOB LIBRN_DIR "${BUILD_DIR}/react-native-0*/jni/${ANDROID_ABI}")

target_link_libraries(
  ${PACKAGE_NAME}
  ReactAndroid::turbomodulejsijni
  fbjni::fbjni                           # <-- fbjni
  ${LOG_LIB}                             # <-- Logcat logger
  ReactAndroid::jsi                      # <-- RN: JSI
  ReactAndroid::reactnativejni           # <-- RN: React Native JNI bindings
  ReactAndroid::react_nativemodule_core  # <-- RN: React Native native module core
  android                                # <-- Android JNI core
  openssl::crypto                        # <-- OpenSSL (Crypto)
)
