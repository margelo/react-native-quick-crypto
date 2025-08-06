cmake_minimum_required(VERSION 3.28)
project(ncrypto)

include(CTest)
include(GNUInstallDirs)
include(FetchContent)
include(cmake/ncrypto-flags.cmake)

if (NOT CMAKE_BUILD_TYPE)
  message(STATUS "No build type selected, default to Release")
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
endif()

include(cmake/CPM.cmake)

CPMAddPackage(
    NAME boringssl
    VERSION 0.20250114.0
    GITHUB_REPOSITORY google/boringssl
    GIT_TAG 0.20250114.0
    OPTIONS "BUILD_SHARED_LIBS OFF" "BUILD_TESTING OFF"
)
add_subdirectory(src)
add_library(ncrypto::ncrypto ALIAS ncrypto)

include_directories(${boringssl_SOURCE_DIR}/include)

if (NCRYPTO_TESTING)
  CPMAddPackage(
      NAME GTest
      GITHUB_REPOSITORY google/googletest
      VERSION 1.15.2
      OPTIONS  "BUILD_GMOCK OFF" "INSTALL_GTEST OFF"
  )
  # For Windows: Prevent overriding the parent project's compiler/linker settings
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  enable_testing()
  add_subdirectory(tests)
endif()

install(
  FILES include/ncrypto.h
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
  COMPONENT ncrypto_development
)

install(
  TARGETS ncrypto
  EXPORT ncrypto_targets
  RUNTIME COMPONENT ncrypto_runtime
  LIBRARY COMPONENT ncrypto_runtime
  NAMELINK_COMPONENT ncrypto_development
  ARCHIVE COMPONENT ncrypto_development
  INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)
