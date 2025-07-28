cmake_minimum_required(VERSION 3.10.0)
project(QuickCrypto)

set(PACKAGE_NAME QuickCrypto)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 20)

# Define C++ library and add all sources
add_library(
  ${PACKAGE_NAME} SHARED
  src/main/cpp/cpp-adapter.cpp
  ../cpp/cipher/CCMCipher.cpp
  ../cpp/cipher/HybridCipher.cpp
  ../cpp/cipher/OCBCipher.cpp
  ../cpp/cipher/XSalsa20Cipher.cpp
  ../cpp/cipher/ChaCha20Cipher.cpp
  ../cpp/cipher/ChaCha20Poly1305Cipher.cpp
  ../cpp/ed25519/HybridEdKeyPair.cpp
  ../cpp/hash/HybridHash.cpp
  ../cpp/hmac/HybridHmac.cpp
  ../cpp/keys/HybridKeyObjectHandle.cpp
  ../cpp/pbkdf2/HybridPbkdf2.cpp
  ../cpp/random/HybridRandom.cpp
  ../deps/fastpbkdf2/fastpbkdf2.c
)

# add Nitrogen specs
include(${CMAKE_SOURCE_DIR}/../nitrogen/generated/android/QuickCrypto+autolinking.cmake)

# local includes
include_directories(
  "src/main/cpp"
  "../cpp/cipher"
  "../cpp/ed25519"
  "../cpp/hash"
  "../cpp/hmac"
  "../cpp/keys"
  "../cpp/pbkdf2"
  "../cpp/random"
  "../cpp/utils"
  "../deps/fastpbkdf2"
  "../deps/ncrypto"
  "../build/includes" # flattened Nitro Modules headers
  "../../../node_modules/react-native/ReactCommon/jsi"
)

# Third party libraries (Prefabs)
find_library(LOG_LIB log)

find_package(openssl REQUIRED CONFIG)

# Link all libraries together
target_link_libraries(
  ${PACKAGE_NAME}
  ${LOG_LIB}                               # <-- Logcat logger
  android                                  # <-- Android core
  openssl::crypto                          # <-- OpenSSL   (Crypto)
)

if(SODIUM_ENABLED)
  add_definitions(-DBLSALLOC_SODIUM)
  find_package(sodium REQUIRED CONFIG)
  target_link_libraries(
    ${PACKAGE_NAME}
    sodium::sodium
  )
endif()

if(ReactAndroid_VERSION_MINOR GREATER_EQUAL 76)
  target_link_libraries(
    ${PACKAGE_NAME}
    ReactAndroid::reactnative              # <-- RN: Native Modules umbrella prefab
  )
else()
  target_link_libraries(
    ${PACKAGE_NAME}
    ReactAndroid::react_nativemodule_core  # <-- RN: TurboModules Core
    ReactAndroid::turbomodulejsijni        # <-- RN: TurboModules utils (e.g. CallInvokerHolder)
  )
endif()
