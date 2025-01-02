project(ReactNativeQuickCrypto)
cmake_minimum_required(VERSION 3.9.0)

set(PACKAGE_NAME "reactnativequickcrypto")
set(BUILD_DIR ${CMAKE_SOURCE_DIR}/build)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 17)

# Define C++ library and add all sources
add_library(
  ${PACKAGE_NAME} SHARED
  src/main/cpp/cpp-adapter.cpp
  ../cpp/MGLQuickCryptoHostObject.cpp
  ../cpp/JSIUtils/MGLTypedArray.cpp
  ../cpp/Utils/MGLDispatchQueue.cpp
  ../cpp/JSIUtils/MGLThreadAwareHostObject.cpp
  ../cpp/JSIUtils/MGLSmartHostObject.cpp
  ../cpp/HMAC/MGLHmacInstaller.cpp
  ../cpp/HMAC/MGLHmacHostObject.cpp
  ../cpp/fastpbkdf2/MGLPbkdf2HostObject.cpp
  ../cpp/fastpbkdf2/fastpbkdf2.c
  ../cpp/Random/MGLRandomHostObject.cpp
  ../cpp/Hash/MGLHashInstaller.cpp
  ../cpp/Hash/MGLHashHostObject.cpp
  ../cpp/Cipher/MGLCipherHostObject.cpp
  ../cpp/Cipher/MGLCreateCipherInstaller.cpp
  ../cpp/Cipher/MGLCreateDecipherInstaller.cpp
  ../cpp/MGLKeys.cpp
  ../cpp/Utils/MGLUtils.cpp
  ../cpp/Cipher/MGLRsa.cpp
  ../cpp/Cipher/MGLGenerateKeyPairInstaller.cpp
  ../cpp/Cipher/MGLGenerateKeyPairSyncInstaller.cpp
  ../cpp/Sig/MGLSignInstaller.cpp
  ../cpp/Sig/MGLVerifyInstaller.cpp
  ../cpp/Sig/MGLSignHostObjects.cpp
  ../cpp/webcrypto/MGLWebCrypto.cpp
  ../cpp/webcrypto/crypto_aes.cpp
  ../cpp/webcrypto/crypto_ec.cpp
  ../cpp/webcrypto/crypto_keygen.cpp
)

# local includes
include_directories(
  src/main/cpp
  ../cpp
  ../cpp/Cipher
  ../cpp/fastpbkdf2
  ../cpp/Hash
  ../cpp/HMAC
  ../cpp/JSIUtils
  ../cpp/Random
  ../cpp/Sig
  ../cpp/Utils
  ../cpp/webcrypto
)

# Third party libraries (Prefabs)
find_library(LOG_LIB log)
find_package(openssl REQUIRED CONFIG)
find_package(fbjni REQUIRED CONFIG)
find_package(ReactAndroid REQUIRED CONFIG)


target_link_libraries(
  ${PACKAGE_NAME}
  ${LOG_LIB}                                  # <-- Logcat logger
  android                                     # <-- Android JNI core
  fbjni::fbjni                                # <-- Facebook C++ JNI helpers
  ReactAndroid::jsi                           # <-- RN: JSI
  openssl::crypto                             # <-- OpenSSL (Crypto)
)

if(ReactAndroid_VERSION_MINOR GREATER_EQUAL 76)
  target_link_libraries(
    ${PACKAGE_NAME}
    ReactAndroid::reactnative                 # <-- RN: Native Modules umbrella prefab
  )
else()
  target_link_libraries(
    ${PACKAGE_NAME}
    ReactAndroid::react_nativemodule_core     # <-- RN: TurboModules Core
    ReactAndroid::turbomodulejsijni           # <-- RN: TurboModules utils (e.g. CallInvokerHolder)
)
endif()
