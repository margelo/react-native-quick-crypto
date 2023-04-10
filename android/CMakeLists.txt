project(react-native-quick-crypto)
cmake_minimum_required(VERSION 3.9.0)

set(PACKAGE_NAME "reactnativequickcrypto")
set(BUILD_DIR ${CMAKE_SOURCE_DIR}/build)
set(CMAKE_CXX_STANDARD 17)

# TODO(osp) remove before release
# set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g")
# set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")

# Consume shared libraries and headers from prefabs
find_package(fbjni REQUIRED CONFIG)
find_package(ReactAndroid REQUIRED CONFIG)

include_directories(
        ../cpp
        "${NODE_MODULES_DIR}/react-native/ReactAndroid/src/main/jni/react/turbomodule"
        "${NODE_MODULES_DIR}/react-native/ReactCommon"
        "${NODE_MODULES_DIR}/react-native/ReactCommon/callinvoker"
        "${NODE_MODULES_DIR}/react-native/ReactCommon/jsi"
        "${NODE_MODULES_DIR}/react-native/ReactCommon/turbomodule/core"
        "${NODE_MODULES_DIR}/react-native/ReactCommon/react/nativemodule/core"
)

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
)

set_target_properties(
        ${PACKAGE_NAME}
        PROPERTIES
        CXX_STANDARD 17
        CXX_EXTENSIONS OFF
        POSITION_INDEPENDENT_CODE ON
)

file(GLOB LIBRN_DIR "${BUILD_DIR}/react-native-0*/jni/${ANDROID_ABI}")

find_library(
        log-lib
        log
)

find_package(openssl REQUIRED CONFIG)

target_link_libraries(
        ${PACKAGE_NAME}
        ReactAndroid::turbomodulejsijni
        fbjni::fbjni
        ${log-lib}
        ReactAndroid::jsi
        ReactAndroid::reactnativejni
        ReactAndroid::react_nativemodule_core
        android
        openssl::crypto
)
