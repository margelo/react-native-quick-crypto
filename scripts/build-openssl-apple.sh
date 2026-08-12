#!/usr/bin/env bash
#
# Builds a static OpenSSL for every Apple platform QuickCrypto supports, renames
# every one of its global symbols to `rnqc_*`, and makes the original names
# local to the archive.
#
# Why: QuickCrypto is a source-built CocoaPod, so it has no link step of its own
# — its OpenSSL references are resolved when the *app* links. If anything else
# in the app statically embeds OpenSSL, ld resolves first-wins and QuickCrypto
# silently ends up running on a foreign OpenSSL with different struct layouts.
# See https://github.com/margelo/react-native-quick-crypto/issues/1059.
#
# After this, QuickCrypto calls `rnqc_EVP_*`, which nothing else defines, so the
# two copies cannot see each other in either direction. Renaming at link level
# (rather than with a `-include` prefix header at compile time, BoringSSL-style)
# is what lets us cover the perlasm symbols too — the preprocessor can't reach
# `.globl _sha256_block_data_order`.
#
# Outputs build/openssl-apple/QuickCryptoOpenSSL.xcframework.zip, which
# QuickCrypto.podspec downloads from a GitHub release.
#
# Usage: scripts/build-openssl-apple.sh [openssl-version]

set -euo pipefail

OPENSSL_VERSION="${1:-3.6.2}"
SYMBOL_PREFIX="rnqc_"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$ROOT/build/openssl-apple"
SRC="$WORK/openssl-$OPENSSL_VERSION"
JOBS="$(sysctl -n hw.ncpu)"

# Deployment targets are deliberately at or below QuickCrypto's own: a static
# archive built for an older minimum links cleanly into a newer app, not the
# reverse.
#
# variant | sdk | platform_version name | archs | target triple suffix | extra Configure opts
SLICES=(
  "ios-arm64|iphoneos|ios|arm64|apple-ios12.0|"
  "ios-arm64_x86_64-simulator|iphonesimulator|ios-simulator|arm64 x86_64|apple-ios12.0-simulator|"
  "macos-arm64_x86_64|macosx|macos|arm64 x86_64|apple-macos10.15|"
  "tvos-arm64|appletvos|tvos|arm64|apple-tvos13.4|no-async"
  "tvos-arm64_x86_64-simulator|appletvsimulator|tvos-simulator|arm64 x86_64|apple-tvos13.4-simulator|no-async"
  "xros-arm64|xros|xros|arm64|apple-xros1.0|no-async"
  "xros-arm64_x86_64-simulator|xrsimulator|xros-simulator|arm64 x86_64|apple-xros1.0-simulator|no-async"
)

fetch_source() {
  mkdir -p "$WORK"
  [ -d "$SRC" ] && return
  local tarball="$WORK/openssl-$OPENSSL_VERSION.tar.gz"
  local base="https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION"
  echo "==> Downloading OpenSSL $OPENSSL_VERSION"
  curl -sSfL -o "$tarball" "$base/openssl-$OPENSSL_VERSION.tar.gz"
  curl -sSfL -o "$tarball.sha256" "$base/openssl-$OPENSSL_VERSION.tar.gz.sha256"
  echo "$(cut -d' ' -f1 <"$tarball.sha256")  $tarball" | shasum -a 256 -c -
  tar xzf "$tarball" -C "$WORK"
}

# Builds libcrypto.a + libssl.a for one arch of one slice.
build_arch() {
  local sdk="$1" arch="$2" triple_suffix="$3" extra="$4" out="$5"
  local sysroot cc
  sysroot="$(xcrun --sdk "$sdk" --show-sdk-path)"
  cc="$(xcrun --sdk "$sdk" -f clang) -target $arch-$triple_suffix -isysroot $sysroot"

  local config_target
  case "$arch" in
    arm64) config_target="darwin64-arm64-cc" ;;
    x86_64) config_target="darwin64-x86_64-cc" ;;
    *) echo "unsupported arch $arch" >&2; exit 1 ;;
  esac

  rm -rf "$out"
  mkdir -p "$out"
  (
    cd "$out"
    # -fPIC because these archives get linked into the app's binary.
    # -fno-common because ld64 emits an *undefined* alias for a common symbol,
    # so tentative definitions have to become real ones before we rename them.
    # OpenSSL declares all of these extern in a header, so there is exactly one
    # definition per symbol and nothing to collide.
    CC="$cc" "$SRC/Configure" "$config_target" \
      no-shared no-tests no-apps \
      ${extra:+$extra} \
      -fPIC -fno-common \
      --prefix="$out/install" --openssldir="$out/install" >configure.log
    make -j"$JOBS" >build.log 2>&1
    make install_dev >install.log 2>&1
  )
}

# Renames every global symbol in the slice's archives to $SYMBOL_PREFIX* and
# demotes the originals to non-external, producing a single static library.
prefix_arch() {
  local out="$1" arch="$2" platform="$3" sdk="$4" min="$5"
  local lib="$out/install/lib"
  local syms="$out/symbols.txt" aliases="$out/aliases.txt"

  # `nm -g --defined-only` prints "<addr> <type> <name>". Every defined global
  # gets demoted to non-external, but only the non-common ones get an alias:
  # ld64 emits an *undefined* alias for a common symbol (type C), which would
  # leave the merged object unlinkable. Commons are all OpenSSL-internal, and
  # demoting them is enough to keep them from colliding.
  xcrun nm -g --defined-only "$lib/libcrypto.a" "$lib/libssl.a" \
    | awk 'NF == 3 && $3 ~ /^_/ { print $2, $3 }' | sort -u -k2 >"$out/nm.txt"
  awk '{print $2}' "$out/nm.txt" | sort -u >"$syms"
  awk -v p="_$SYMBOL_PREFIX" '$1 != "C" {print $2" "p substr($2,2)}' "$out/nm.txt" \
    | sort -u >"$aliases"

  xcrun ld -r -o "$out/openssl.o" \
    -all_load "$lib/libcrypto.a" "$lib/libssl.a" \
    -arch "$arch" \
    -syslibroot "$(xcrun --sdk "$sdk" --show-sdk-path)" \
    -platform_version "$platform" "$min" "$min" \
    -alias_list "$aliases" \
    -unexported_symbols_list "$syms"

  xcrun libtool -static -o "$out/libQuickCryptoOpenSSL.a" "$out/openssl.o"
}

fetch_source

DIST="$WORK/dist"
rm -rf "$WORK/xcframework" "$DIST" "$WORK/all-symbols.txt"
mkdir -p "$WORK/xcframework" "$DIST"
create_args=()

for slice in "${SLICES[@]}"; do
  IFS='|' read -r variant sdk platform archs triple_suffix extra <<<"$slice"
  min="${triple_suffix##*-apple-}"
  min="${min%-simulator}"
  min="$(echo "$min" | tr -dc '0-9.')"

  echo "==> Building $variant"
  arch_libs=()
  for arch in $archs; do
    out="$WORK/$variant/$arch"
    build_arch "$sdk" "$arch" "$triple_suffix" "$extra" "$out"
    prefix_arch "$out" "$arch" "$platform" "$sdk" "$min"
    arch_libs+=("$out/libQuickCryptoOpenSSL.a")
    awk '{print $1}' "$out/aliases.txt" >>"$WORK/all-symbols.txt"
    # Every slice we build is 64-bit, so the generated headers (configuration.h,
    # bn_conf.h) are identical across them — one copy serves all.
    [ -d "$DIST/include" ] || cp -R "$out/install/include" "$DIST/include"
  done

  mkdir -p "$WORK/xcframework/$variant"
  xcrun lipo -create "${arch_libs[@]}" -output "$WORK/xcframework/$variant/libQuickCryptoOpenSSL.a"
  create_args+=(-library "$WORK/xcframework/$variant/libQuickCryptoOpenSSL.a")
done

# The header QuickCrypto force-includes so its sources call the renamed symbols.
# Only symbols reachable from OpenSSL's public headers get a #define: these
# macros apply to every token in every QuickCrypto translation unit, so renaming
# an internal name like `sha256_block_data_order` would risk clobbering an
# unrelated identifier of ours for no gain — internal symbols are only reached
# from inside OpenSSL, where the link-level alias already covers them.
sort -u "$WORK/all-symbols.txt" | sed 's/^_//' | sort -u >"$WORK/symbols.all"
# Identifiers are collected from the *preprocessed* headers, not their text. A
# large part of OpenSSL's public API is generated by token pasting —
# DECLARE_ASN1_FUNCTIONS(X509) produces X509_free/d2i_X509/i2d_X509,
# DECLARE_PEM_write_bio produces PEM_write_bio_X509 — so those names never
# appear literally in a header and reading the text alone silently drops the
# entire ASN.1 and PEM surface.
for h in "$DIST"/include/openssl/*.h; do
  echo "#include <openssl/$(basename "$h")>"
done >"$WORK/all-headers.h"
xcrun clang -E -I"$DIST/include" -x c "$WORK/all-headers.h" -o "$WORK/headers.pp"
grep -ohE '\b[A-Za-z_][A-Za-z0-9_]*\b' "$WORK/headers.pp" | sort -u >"$WORK/header.idents"
# Names OpenSSL's own headers #define (EVP_des_cfb -> EVP_des_cfb64) are skipped:
# that macro already redirects to a symbol we do rename, and defining both just
# collides.
sed -nE 's/^[[:space:]]*#[[:space:]]*define[[:space:]]+([A-Za-z_][A-Za-z0-9_]*).*/\1/p' \
  "$DIST"/include/openssl/*.h | sort -u >"$WORK/header.macros"
{
  echo "// Generated by scripts/build-openssl-apple.sh — do not edit."
  echo "// OpenSSL $OPENSSL_VERSION"
  echo "#pragma once"
  comm -12 "$WORK/symbols.all" "$WORK/header.idents" |
    comm -23 - "$WORK/header.macros" |
    sed "s/^\(.*\)$/#define \1 $SYMBOL_PREFIX\1/"
} >"$DIST/quickcrypto_openssl_prefix.h"

xcrun xcodebuild -create-xcframework "${create_args[@]}" \
  -output "$DIST/QuickCryptoOpenSSL.xcframework"

ZIP="$WORK/QuickCryptoOpenSSL-$OPENSSL_VERSION.zip"
(cd "$DIST" && rm -f "$ZIP" && zip -qry "$ZIP" .)

echo "==> $ZIP"
shasum -a 256 "$ZIP"
