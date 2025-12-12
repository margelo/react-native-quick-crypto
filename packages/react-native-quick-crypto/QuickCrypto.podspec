require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::UI.puts "[QuickCrypto]  💨 crypto just got quicker"

Pod::Spec.new do |s|
  s.name         = "QuickCrypto"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["authors"]

  s.ios.deployment_target = min_ios_version_supported
  s.visionos.deployment_target = 1.0
  s.macos.deployment_target = 10.13
  s.tvos.deployment_target = 13.4

  s.source = { :git => "https://github.com/margelo/react-native-quick-crypto.git", :tag => "#{s.version}" }

  sodium_enabled = ENV['SODIUM_ENABLED'] == '1'
  Pod::UI.puts("[QuickCrypto]  🧂 has libsodium #{sodium_enabled ? "enabled" : "disabled"}!")

  # OpenSSL 3.6+ vendored xcframework (not yet on CocoaPods trunk)
  openssl_version = "3.6.0000"
  openssl_url = "https://github.com/krzyzanowskim/OpenSSL/releases/download/#{openssl_version}/OpenSSL.xcframework.zip"

  if sodium_enabled
    # Build libsodium from source for XSalsa20 cipher support
    # CocoaPods packages are outdated (1.0.12) and SPM causes module conflicts
    s.prepare_command = <<-CMD
      set -e
      # Download OpenSSL.xcframework
      if [ ! -d "OpenSSL.xcframework" ]; then
        curl -L -o OpenSSL.xcframework.zip #{openssl_url}
        unzip -o OpenSSL.xcframework.zip
        rm -f OpenSSL.xcframework.zip
      fi
      # Build libsodium
      mkdir -p ios
      curl -L -o ios/libsodium.tar.gz https://download.libsodium.org/libsodium/releases/libsodium-1.0.20-stable.tar.gz
      tar -xzf ios/libsodium.tar.gz -C ios
      cd ios/libsodium-stable
      ./configure --disable-shared --enable-static
      make -j$(sysctl -n hw.ncpu)
      cd ../../
      rm -f ios/libsodium.tar.gz
    CMD
  else
    s.prepare_command = <<-CMD
      set -e
      # Download OpenSSL.xcframework
      if [ ! -d "OpenSSL.xcframework" ]; then
        curl -L -o OpenSSL.xcframework.zip #{openssl_url}
        unzip -o OpenSSL.xcframework.zip
        rm -f OpenSSL.xcframework.zip
      fi
      # Clean up libsodium if previously built
      rm -rf ios/libsodium-stable
      rm -f ios/libsodium.tar.gz
    CMD
  end

  s.vendored_frameworks = "OpenSSL.xcframework"

  base_source_files = [
    # implementation (Swift)
    "ios/**/*.{swift}",
    # ios (Objective-C++)
    "ios/**/*.{h,m,mm}",
    # implementation (C++)
    "cpp/**/*.{hpp,cpp}",
    # dependencies (C++) - ncrypto
    "deps/ncrypto/include/*.{h}",
    "deps/ncrypto/src/*.{cpp}",
    # dependencies (C) - exclude BLAKE3 x86 SIMD files (only use portable + NEON for ARM)
    "deps/blake3/c/*.{h,c}",
    "deps/fastpbkdf2/*.{h,c}",
  ]

  # Exclude BLAKE3 x86-specific SIMD implementations (SSE2, SSE4.1, AVX2, AVX-512)
  # These use Intel intrinsics that don't compile on ARM
  # Also exclude example files, TBB files, test files, and non-C directories
  s.exclude_files = [
    "deps/blake3/c/blake3_sse2.c",
    "deps/blake3/c/blake3_sse41.c",
    "deps/blake3/c/blake3_avx2.c",
    "deps/blake3/c/blake3_avx512.c",
    "deps/blake3/c/blake3_sse2_x86-64_unix.S",
    "deps/blake3/c/blake3_sse41_x86-64_unix.S",
    "deps/blake3/c/blake3_avx2_x86-64_unix.S",
    "deps/blake3/c/blake3_avx512_x86-64_unix.S",
    "deps/blake3/c/blake3_sse2_x86-64_windows_gnu.S",
    "deps/blake3/c/blake3_sse41_x86-64_windows_gnu.S",
    "deps/blake3/c/blake3_avx2_x86-64_windows_gnu.S",
    "deps/blake3/c/blake3_avx512_x86-64_windows_gnu.S",
    "deps/blake3/c/blake3_sse2_x86-64_windows_msvc.asm",
    "deps/blake3/c/blake3_sse41_x86-64_windows_msvc.asm",
    "deps/blake3/c/blake3_avx2_x86-64_windows_msvc.asm",
    "deps/blake3/c/blake3_avx512_x86-64_windows_msvc.asm",
    "deps/blake3/c/main.c",
    "deps/blake3/c/example.c",
    "deps/blake3/c/example_tbb.c",
    "deps/blake3/c/blake3_tbb.cpp",
    # Exclude non-C parts of BLAKE3 repo (Rust, benchmarks, tools, etc.)
    "deps/blake3/src/**/*",
    "deps/blake3/b3sum/**/*",
    "deps/blake3/benches/**/*",
    "deps/blake3/reference_impl/**/*",
    "deps/blake3/tools/**/*",
    "deps/blake3/test_vectors/**/*",
  ]

  if sodium_enabled
    base_source_files += ["ios/libsodium-stable/src/libsodium/**/*.{h,c}"]
  end

  s.source_files = base_source_files

  xcconfig = {
    # C++ compiler flags, mainly for folly.
    "GCC_PREPROCESSOR_DEFINITIONS" => "$(inherited) FOLLY_NO_CONFIG FOLLY_CFG_NO_COROUTINES",
    # Set C++ standard to C++20
    "CLANG_CXX_LANGUAGE_STANDARD" => "c++20",
    "CLANG_ALLOW_NON_MODULAR_INCLUDES_IN_FRAMEWORK_MODULES" => "YES"
  }

  # Add cpp subdirectories to header search paths
  cpp_headers = [
    "\"$(PODS_TARGET_SRCROOT)/cpp/utils\"",
    "\"$(PODS_TARGET_SRCROOT)/cpp/hkdf\"",
    "\"$(PODS_TARGET_SRCROOT)/deps/ncrypto/include\"",
    "\"$(PODS_TARGET_SRCROOT)/deps/blake3/c\"",
    "\"$(PODS_TARGET_SRCROOT)/deps/fastpbkdf2\""
  ]

  if sodium_enabled
    sodium_headers = [
      "\"$(PODS_TARGET_SRCROOT)/ios/libsodium-stable/src/libsodium/include\"",
      "\"$(PODS_TARGET_SRCROOT)/ios/libsodium-stable/src/libsodium/include/sodium\"",
      "\"$(PODS_TARGET_SRCROOT)/ios/libsodium-stable\"",
      "\"$(PODS_ROOT)/../../packages/react-native-quick-crypto/ios/libsodium-stable/src/libsodium/include\"",
      "\"$(PODS_ROOT)/../../packages/react-native-quick-crypto/ios/libsodium-stable/src/libsodium/include/sodium\""
    ]
    xcconfig["HEADER_SEARCH_PATHS"] = (cpp_headers + sodium_headers).join(' ')
    xcconfig["GCC_PREPROCESSOR_DEFINITIONS"] = "$(inherited) FOLLY_NO_CONFIG FOLLY_CFG_NO_COROUTINES BLSALLOC_SODIUM=1"
  else
    xcconfig["HEADER_SEARCH_PATHS"] = cpp_headers.join(' ')
  end

  s.pod_target_xcconfig = xcconfig

  # Add all files generated by Nitrogen
  load "nitrogen/generated/ios/QuickCrypto+autolinking.rb"
  add_nitrogen_files(s)

  s.dependency "React-jsi"
  s.dependency "React-callinvoker"

  install_modules_dependencies(s)
end
