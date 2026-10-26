#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ncrypto_dir="$repo_root/packages/react-native-quick-crypto/deps/ncrypto"
compiler="${CXX:-c++}"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

openssl_cflags=()
openssl_ldflags=()
if [[ -n "${OPENSSL_ROOT_DIR:-}" ]]; then
  openssl_cflags+=("-I$OPENSSL_ROOT_DIR/include")
  if [[ -d "$OPENSSL_ROOT_DIR/lib" ]]; then
    openssl_lib_dir="$OPENSSL_ROOT_DIR/lib"
  else
    openssl_lib_dir="$OPENSSL_ROOT_DIR/lib64"
  fi
  openssl_ldflags+=("-L$openssl_lib_dir" "-Wl,-rpath,$openssl_lib_dir" -lssl -lcrypto)
  if [[ "$(uname -s)" == "Linux" ]]; then
    openssl_ldflags+=(-ldl -pthread)
  fi
elif command -v pkg-config >/dev/null 2>&1 && pkg-config --exists openssl; then
  read -r -a openssl_cflags <<<"$(pkg-config --cflags openssl)"
  read -r -a openssl_ldflags <<<"$(pkg-config --libs openssl)"
elif command -v brew >/dev/null 2>&1; then
  openssl_prefix="$(brew --prefix openssl@3)"
  openssl_cflags+=("-I$openssl_prefix/include")
  openssl_ldflags+=("-L$openssl_prefix/lib" "-Wl,-rpath,$openssl_prefix/lib" -lssl -lcrypto)
else
  openssl_ldflags+=(-lssl -lcrypto)
fi

cat >"$work_dir/header-consumer.cpp" <<'EOF'
#include <ncrypto.h>
#include <ncrypto/aead.h>

static_assert(OPENSSL_VERSION_NUMBER >= 0x30600000L);
static_assert(NCRYPTO_EVP_ONLY == 1);
EOF

cat >"$work_dir/prime-check-regression.cpp" <<'EOF'
#include <ncrypto.h>

namespace {
bool checkMersennePrime(int exponent, int requested_checks) {
  ncrypto::BignumPointer candidate(BN_new());
  if (!candidate || BN_set_bit(candidate.get(), exponent) != 1 ||
      BN_sub_word(candidate.get(), 1) != 1) {
    return false;
  }

  int completed_checks = 0;
  const int result = candidate.isPrime(
      requested_checks, [&completed_checks](int event, int iteration) {
        if (event == 1 && iteration >= 0) completed_checks++;
        return true;
      });
  return result == 1 && completed_checks >= requested_checks;
}
}  // namespace

int main() {
  return checkMersennePrime(127, 65) && checkMersennePrime(2203, 129) ? 0 : 1;
}
EOF

warning_flags=(
  -std=c++20
  -Wall
  -Wextra
  -Werror
  -Wdeprecated-declarations
  -DNCRYPTO_EVP_ONLY=1
  "-I$ncrypto_dir/include"
  "${openssl_cflags[@]}"
)

"$compiler" "${warning_flags[@]}" -fsyntax-only "$ncrypto_dir/src/ncrypto.cpp"
"$compiler" "${warning_flags[@]}" -fsyntax-only "$ncrypto_dir/src/aead.cpp"
"$compiler" "${warning_flags[@]}" -fsyntax-only "$ncrypto_dir/src/engine.cpp"
"$compiler" "${warning_flags[@]}" -fsyntax-only "$work_dir/header-consumer.cpp"
"$compiler" "${warning_flags[@]}" \
  "$ncrypto_dir/src/ncrypto.cpp" \
  "$work_dir/prime-check-regression.cpp" \
  "${openssl_ldflags[@]}" \
  -o "$work_dir/prime-check-regression"
"$work_dir/prime-check-regression"
