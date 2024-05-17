project(ReactNativeQuickCrypto)
cmake_minimum_required(VERSION 3.10.2)

set(PACKAGE_NAME "reactnativequickcrypto")
set(BUILD_DIR ${CMAKE_SOURCE_DIR}/build)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 17)

# set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g")
# set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")


# Third party libraries (Prefabs)
find_package(fbjni REQUIRED CONFIG)
find_package(ReactAndroid REQUIRED CONFIG)
#find_package(openssl REQUIRED CONFIG)
find_library(LOG_LIB log)

# Stuff for openssl workaround
set(OPENSSL_ROOT_DIR ${CMAKE_SOURCE_DIR}/src/main/cpp/openssl)
if(${ANDROID_ABI} STREQUAL "armeabi-v7a")
    set(OPENSSL_LIB_DIR ${OPENSSL_ROOT_DIR}/libs/armeabi-v7a)
elseif(${ANDROID_ABI} STREQUAL "arm64-v8a")
    set(OPENSSL_LIB_DIR ${OPENSSL_ROOT_DIR}/libs/arm64-v8a)
elseif(${ANDROID_ABI} STREQUAL "x86")
    set(OPENSSL_LIB_DIR ${OPENSSL_ROOT_DIR}/libs/x86)
elseif(${ANDROID_ABI} STREQUAL "x86_64")
    set(OPENSSL_LIB_DIR ${OPENSSL_ROOT_DIR}/libs/x86_64)
else()
    message(FATAL_ERROR "Unsupported ABI: ${ANDROID_ABI}")
endif()

add_library(crypto STATIC IMPORTED)
set_target_properties(crypto PROPERTIES IMPORTED_LOCATION ${OPENSSL_LIB_DIR}/libcrypto.a)
add_library(ssl STATIC IMPORTED)
set_target_properties(ssl PROPERTIES IMPORTED_LOCATION ${OPENSSL_LIB_DIR}/libssl.a)


add_library(
  ${PACKAGE_NAME}
  SHARED
  "src/main/cpp/cpp-adapter.cpp"
  "../cpp/MGLQuickCryptoHostObject.cpp"
  "../cpp/JSIUtils/MGLTypedArray.cpp"
  "../cpp/Utils/MGLDispatchQueue.cpp"
  "../cpp/JSIUtils/MGLThreadAwareHostObject.cpp"
  "../cpp/JSIUtils/MGLSmartHostObject.cpp"
  "../cpp/HMAC/MGLHmacInstaller.cpp"
  "../cpp/HMAC/MGLHmacHostObject.cpp"
  "../cpp/fastpbkdf2/MGLPbkdf2HostObject.cpp"
  "../cpp/fastpbkdf2/fastpbkdf2.c"
  "../cpp/Random/MGLRandomHostObject.cpp"
  "../cpp/Hash/MGLHashInstaller.cpp"
  "../cpp/Hash/MGLHashHostObject.cpp"
  "../cpp/Cipher/MGLCipherHostObject.cpp"
  "../cpp/Cipher/MGLCreateCipherInstaller.cpp"
  "../cpp/Cipher/MGLCreateDecipherInstaller.cpp"
  "../cpp/MGLKeys.cpp"
  "../cpp/Utils/MGLUtils.cpp"
  "../cpp/Cipher/MGLRsa.cpp"
  "../cpp/Cipher/MGLGenerateKeyPairInstaller.cpp"
  "../cpp/Cipher/MGLGenerateKeyPairSyncInstaller.cpp"
  "../cpp/Sig/MGLSignInstaller.cpp"
  "../cpp/Sig/MGLVerifyInstaller.cpp"
  "../cpp/Sig/MGLSignHostObjects.cpp"
  "../cpp/webcrypto/MGLWebCrypto.cpp"
  "../cpp/webcrypto/crypto_ec.cpp"
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
  "${OPENSSL_ROOT_DIR}/include"
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
  crypto                                 # <-- OpenSSL (Crypto)
)