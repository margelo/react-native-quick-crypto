project(QuickCrypto)
cmake_minimum_required(VERSION 3.9.0)

set(PACKAGE_NAME "QuickCrypto")
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 20)

# Add Nitrogen specs :)
include(${CMAKE_SOURCE_DIR}/../nitrogen/generated/android/QuickCrypto+autolinking.cmake)

# Third party libraries (Prefabs)
find_package(openssl REQUIRED CONFIG)
find_library(LOG_LIB log)

add_library(
  ${PACKAGE_NAME}
  SHARED
  "src/main/cpp/cpp-adapter.cpp"
  "../cpp/HybridRandom.cpp"
)

# Link all libraries together
target_link_libraries(
  ${PACKAGE_NAME}
  ${LOG_LIB}                             # <-- Logcat logger
  android                                # <-- Android core
  openssl::crypto                        # <-- OpenSSL (Crypto)
)
