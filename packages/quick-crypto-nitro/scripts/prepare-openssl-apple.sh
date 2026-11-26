#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
version=3.6.2
checksum=a50e3c8473b0526b159ad8d105e97a90d1153a4a230388cc731ee23a7d0ad3a4
mkdir -p ios
stage=$(mktemp -d ios/openssl.XXXXXXXX)
trap 'rm -rf "$stage"' EXIT
archive="$stage/QuickCryptoOpenSSL.zip"
curl --fail --location --retry 3 --output "$archive" \
  "https://github.com/margelo/react-native-quick-crypto/releases/download/openssl-apple-$version/QuickCryptoOpenSSL-$version.zip"
printf '%s  %s\n' "$checksum" "$archive" | shasum -a 256 --check
# The release keeps these headers next to the XCFramework. SwiftPM only exposes the binary.
unzip -q "$archive" 'include/*' quickcrypto_openssl_prefix.h -d "$stage/openssl"
rm -rf ios/openssl
mv "$stage/openssl" ios/openssl
