project(react_codegen_RTNQuickCryptoCxxSpec)
cmake_minimum_required(VERSION 3.13)

set(PACKAGE_NAME "react_codegen_RTNQuickCryptoCxxSpec")
set(BUILD_DIR ${CMAKE_SOURCE_DIR}/build)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 17)

# set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g")
# set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")

find_library(LOG_LIB log)

add_library(
  ${PACKAGE_NAME}
  SHARED
  "../build/generated/source/codegen/jni/RTNQuickCryptoCxxSpec-generated.cpp"
  "./dummy.cpp"
)

target_include_directories(
  ${PACKAGE_NAME}
  PUBLIC
  "../build/generated/source/codegen/jni"
)

target_link_libraries(
  ${PACKAGE_NAME}
  ${LOG_LIB}    
  fbjni
  folly_runtime
  glog
  jsi
  react_codegen_rncore
  react_debug
  react_nativemodule_core
  react_render_componentregistry
  react_render_core
  react_render_debug
  react_render_graphics
  react_render_imagemanager
  react_render_mapbuffer
  react_utils
  rrc_image
  rrc_view
  turbomodulejsijni
  yoga                      
)

target_compile_options(
  react_codegen_RTNQuickCryptoCxxSpec
  PRIVATE
  -DLOG_TAG=\"ReactNative\"
  -fexceptions
  -frtti
  -std=c++20
  -Wall
)

