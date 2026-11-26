#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p cpp/internal
cp ../react-native-quick-crypto/cpp/hash/HashContext.hpp cpp/internal/
