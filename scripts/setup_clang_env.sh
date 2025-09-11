#!/bin/bash

set -e

# Get the directory of this script file
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Set BUILD_DIR to the packages/react-native-quick-crypto/build directory
BUILD_DIR="$SCRIPT_DIR/../packages/react-native-quick-crypto/build"

# Create build directory if it doesn't exist
mkdir -p "$BUILD_DIR"

# Convert to absolute path
BUILD_DIR="$(cd "$BUILD_DIR" && pwd)"

# Set PKG_DIR to the packages/react-native-quick-crypto directory
PKG_DIR="$SCRIPT_DIR/../packages/react-native-quick-crypto"

# Convert to absolute path
PKG_DIR="$(cd "$PKG_DIR" && pwd)"

# Flatten Nitrogen headers
$SCRIPT_DIR/flatten-nitro-headers.sh

# Create a clean CMakeLists.txt for IDE support with explicit lists
cat > "$PKG_DIR/CMakeLists.txt" << 'EOF'
cmake_minimum_required(VERSION 3.10.0)
project(QuickCrypto)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Include directories
include_directories(
  "android/src/main/cpp"
  "cpp/cipher"
  "cpp/ed25519"
  "cpp/hash"
  "cpp/hmac"
  "cpp/keys"
  "cpp/pbkdf2"
  "cpp/random"
  "cpp/utils"
  "deps/fastpbkdf2"
  "deps/ncrypto"
  "build/includes"
  "nitrogen/generated/shared/c++"
  "../../node_modules/react-native/ReactCommon/jsi"
)

# Source files
add_library(QuickCrypto STATIC
  android/src/main/cpp/cpp-adapter.cpp
  cpp/cipher/CCMCipher.cpp
  cpp/cipher/HybridCipher.cpp
  cpp/cipher/OCBCipher.cpp
  cpp/cipher/XSalsa20Cipher.cpp
  cpp/cipher/ChaCha20Cipher.cpp
  cpp/cipher/ChaCha20Poly1305Cipher.cpp
  cpp/ed25519/HybridEdKeyPair.cpp
  cpp/hash/HybridHash.cpp
  cpp/hmac/HybridHmac.cpp
  cpp/keys/HybridKeyObjectHandle.cpp
  cpp/pbkdf2/HybridPbkdf2.cpp
  cpp/random/HybridRandom.cpp
  deps/fastpbkdf2/fastpbkdf2.c
  deps/ncrypto/ncrypto.cc
)
EOF

# Generate compile_commands.json (run from package root, build in build dir)
cmake -S "$PKG_DIR" -B "$BUILD_DIR"

# Copy the generated compile_commands.json to the project root
cp "$BUILD_DIR/compile_commands.json" "$PKG_DIR/compile_commands.json"

# Clean up the temporary CMakeLists.txt
rm "$PKG_DIR/CMakeLists.txt"

echo "Generated compile_commands.json for IDE support"
