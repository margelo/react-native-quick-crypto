find_package(opensslstatic REQUIRED CONFIG)

# The host runtime's libwebsockets supplies OpenSSL-compatible symbols of its own.
# Give Quick Crypto a private copy of libcrypto behind the hash backend's ABI.
set(quickcrypto_backend_dir "${CMAKE_CURRENT_LIST_DIR}/../backend")
add_library(QuickCryptoHashBackend SHARED "${quickcrypto_backend_dir}/HashBackend.cpp")
set_target_properties(QuickCryptoHashBackend PROPERTIES CXX_VISIBILITY_PRESET hidden VISIBILITY_INLINES_HIDDEN YES)
target_include_directories(QuickCryptoHashBackend PUBLIC "${quickcrypto_backend_dir}")
target_link_libraries(QuickCryptoHashBackend PRIVATE opensslstatic::crypto)
target_link_options(QuickCryptoHashBackend PRIVATE "LINKER:--exclude-libs,libcrypto.a")

target_include_directories(QuickCryptoNitro PRIVATE "${CMAKE_CURRENT_LIST_DIR}/../cpp/include")
target_link_libraries(QuickCryptoNitro QuickCryptoHashBackend)
