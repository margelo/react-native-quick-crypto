cmake_minimum_required(VERSION 3.9.0)

project(QuickCrypto)
set(PACKAGE_NAME QuickCrypto)

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 20)

# Define C++ library and add all sources
add_library(
  ${PACKAGE_NAME} SHARED
  src/main/cpp/cpp-adapter.cpp
  ../cpp/random/HybridRandom.cpp
)

include_directories(../cpp)
include(${CMAKE_SOURCE_DIR}/../nitrogen/generated/android/QuickCrypto+autolinking.cmake)

# Third party libraries (Prefabs)
find_library(LOG_LIB log)

find_package(ReactAndroid REQUIRED CONFIG)
find_package(fbjni REQUIRED CONFIG)
find_package(openssl REQUIRED CONFIG)

# Link all libraries together
target_link_libraries(
  ${PACKAGE_NAME}
  ${LOG_LIB}                             # <-- Logcat logger
  android                                # <-- Android core
  fbjni::fbjni                           # <-- Facebook C++ JNI helpers
  openssl::crypto                        # <-- OpenSSL (Crypto)
  ReactAndroid::jsi
  ReactAndroid::turbomodulejsijni
  ReactAndroid::react_nativemodule_core
  ReactAndroid::react_render_core
  ReactAndroid::runtimeexecutor
  ReactAndroid::fabricjni
  ReactAndroid::react_debug
  ReactAndroid::react_render_core
  ReactAndroid::react_render_componentregistry
  ReactAndroid::rrc_view
  ReactAndroid::folly_runtime
  )
