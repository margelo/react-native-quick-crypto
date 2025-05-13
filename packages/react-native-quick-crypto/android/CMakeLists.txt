project(QuickCrypto)
cmake_minimum_required(VERSION 3.9.0)

set(PACKAGE_NAME QuickCrypto)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 20)

# # Check if we're in a clean build by looking for Nitro Modules headers
# set(NITRO_MODULES_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/../../node_modules/react-native-nitro-modules/android/build/headers/nitromodules")
# if(NOT EXISTS "${NITRO_MODULES_HEADERS}")
#   message(STATUS "Nitro Modules headers not found at ${NITRO_MODULES_HEADERS} - this is likely a clean build")
#   message(STATUS "Creating minimal build configuration for clean task")
  
#   # Define a minimal library for clean builds
#   add_library(${PACKAGE_NAME} SHARED src/main/cpp/cpp-adapter.cpp)
  
#   # Add minimal dependencies
#   find_library(LOG_LIB log)
#   target_link_libraries(${PACKAGE_NAME} ${LOG_LIB} android)
  
#   # Skip the rest of the configuration
#   return()
# endif()
# # If we get here, we're in a normal build with all dependencies available

# Define C++ library and add all sources
add_library(
  ${PACKAGE_NAME} SHARED
  src/main/cpp/cpp-adapter.cpp
  ../cpp/cipher/CCMCipher.cpp
  ../cpp/cipher/HybridCipher.cpp
  ../cpp/cipher/OCBCipher.cpp
  ../cpp/cipher/XSalsa20Cipher.cpp
  ../cpp/ed25519/HybridEdKeyPair.cpp
  ../cpp/hash/HybridHash.cpp
  ../cpp/hmac/HybridHmac.cpp
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
  "../cpp/pbkdf2"
  "../cpp/random"
  "../cpp/utils"
  "../deps/fastpbkdf2"
)

# Third party libraries (Prefabs)
find_library(LOG_LIB log)

find_package(openssl REQUIRED CONFIG)
find_package(sodium REQUIRED CONFIG)

# Link all libraries together
target_link_libraries(
  ${PACKAGE_NAME}
  ${LOG_LIB}                               # <-- Logcat logger
  android                                  # <-- Android core
  openssl::crypto                          # <-- OpenSSL   (Crypto)
  sodium::sodium                           # <-- libsodium (Crypto)
)

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
