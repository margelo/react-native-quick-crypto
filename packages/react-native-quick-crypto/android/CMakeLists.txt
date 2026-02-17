cmake_minimum_required(VERSION 3.10.0)
project(QuickCrypto)

set(PACKAGE_NAME QuickCrypto)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 20)

# BLAKE3 sources - architecture-specific SIMD support
set(BLAKE3_SOURCES
  ../deps/blake3/c/blake3.c
  ../deps/blake3/c/blake3_dispatch.c
  ../deps/blake3/c/blake3_portable.c
)

if(CMAKE_ANDROID_ARCH_ABI STREQUAL "arm64-v8a")
  # ARM64 uses NEON intrinsics (auto-detected via IS_AARCH64 in blake3_impl.h)
  list(APPEND BLAKE3_SOURCES ../deps/blake3/c/blake3_neon.c)
elseif(CMAKE_ANDROID_ARCH_ABI STREQUAL "x86" OR CMAKE_ANDROID_ARCH_ABI STREQUAL "x86_64")
  # Disable x86 SIMD - would require assembly files we don't compile
  # Falls back to portable C implementation
  add_definitions(-DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41 -DBLAKE3_NO_AVX2 -DBLAKE3_NO_AVX512)
endif()

# Define C++ library and add all sources
add_library(
  ${PACKAGE_NAME} SHARED
  src/main/cpp/cpp-adapter.cpp
  ../cpp/argon2/HybridArgon2.cpp
  ../cpp/blake3/HybridBlake3.cpp
  ../cpp/certificate/HybridCertificate.cpp
  ../cpp/cipher/CCMCipher.cpp
  ../cpp/cipher/GCMCipher.cpp
  ../cpp/cipher/HybridCipher.cpp
  ../cpp/cipher/HybridRsaCipher.cpp
  ../cpp/cipher/OCBCipher.cpp
  ../cpp/cipher/XSalsa20Cipher.cpp
  ../cpp/cipher/XSalsa20Poly1305Cipher.cpp
  ../cpp/cipher/XChaCha20Poly1305Cipher.cpp
  ../cpp/cipher/ChaCha20Cipher.cpp
  ../cpp/cipher/ChaCha20Poly1305Cipher.cpp
  ../cpp/dh/HybridDiffieHellman.cpp
  ../cpp/dh/HybridDhKeyPair.cpp
  ../cpp/dsa/HybridDsaKeyPair.cpp
  ../cpp/ec/HybridEcKeyPair.cpp
  ../cpp/ecdh/HybridECDH.cpp
  ../cpp/ed25519/HybridEdKeyPair.cpp
  ../cpp/hash/HybridHash.cpp
  ../cpp/hmac/HybridHmac.cpp
  ../cpp/hkdf/HybridHkdf.cpp
  ../cpp/keys/HybridKeyObjectHandle.cpp
  ../cpp/keys/KeyObjectData.cpp
  ../cpp/mldsa/HybridMlDsaKeyPair.cpp
  ../cpp/mlkem/HybridMlKemKeyPair.cpp
  ../cpp/pbkdf2/HybridPbkdf2.cpp
  ../cpp/prime/HybridPrime.cpp
  ../cpp/random/HybridRandom.cpp
  ../cpp/rsa/HybridRsaKeyPair.cpp
  ../cpp/scrypt/HybridScrypt.cpp
  ../cpp/sign/HybridSignHandle.cpp
  ../cpp/sign/HybridVerifyHandle.cpp
  ../cpp/x509/HybridX509Certificate.cpp
  ../cpp/utils/HybridUtils.cpp
  ../cpp/utils/QuickCryptoUtils.cpp
  ${BLAKE3_SOURCES}
  ../deps/fastpbkdf2/fastpbkdf2.c
  ../deps/ncrypto/src/aead.cpp
  ../deps/ncrypto/src/engine.cpp
  ../deps/ncrypto/src/ncrypto.cpp
)

# add Nitrogen specs
include(${CMAKE_SOURCE_DIR}/../nitrogen/generated/android/QuickCrypto+autolinking.cmake)

# local includes
include_directories(
  "src/main/cpp"
  "../cpp/argon2"
  "../cpp/blake3"
  "../cpp/certificate"
  "../cpp/cipher"
  "../cpp/dh"
  "../cpp/dsa"
  "../cpp/ec"
  "../cpp/ecdh"
  "../cpp/ed25519"
  "../cpp/hash"
  "../cpp/hkdf"
  "../cpp/hmac"
  "../cpp/keys"
  "../cpp/mldsa"
  "../cpp/mlkem"
  "../cpp/pbkdf2"
  "../cpp/prime"
  "../cpp/random"
  "../cpp/rsa"
  "../cpp/sign"
  "../cpp/scrypt"
  "../cpp/utils"
  "../cpp/x509"
  "../deps/blake3/c"
  "../deps/fastpbkdf2"
  "../deps/ncrypto/include"
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
  openssl::ssl                             # <-- OpenSSL   (SSL)
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
