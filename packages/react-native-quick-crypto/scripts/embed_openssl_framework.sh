#!/bin/bash
set -e

OPENSSL_FRAMEWORK="${BUILT_PRODUCTS_DIR}/OpenSSL.framework"

if [ -d "$OPENSSL_FRAMEWORK" ]; then
  echo "[QuickCrypto] Copying OpenSSL.framework to app bundle"
  mkdir -p "${TARGET_BUILD_DIR}/${FRAMEWORKS_FOLDER_PATH}"
  cp -Rf "$OPENSSL_FRAMEWORK" "${TARGET_BUILD_DIR}/${FRAMEWORKS_FOLDER_PATH}/"
  
  # Code sign the framework (only if code signing is required and not a simulator build)
  if [ "${CODE_SIGNING_REQUIRED}" = "YES" ] && [ "${EFFECTIVE_PLATFORM_NAME}" != "-iphonesimulator" ]; then
    codesign --force --sign "${EXPANDED_CODE_SIGN_IDENTITY}" --preserve-metadata=identifier,entitlements --timestamp=none "${TARGET_BUILD_DIR}/${FRAMEWORKS_FOLDER_PATH}/OpenSSL.framework" || true
  fi
  echo "[QuickCrypto] Successfully embedded OpenSSL.framework"
else
  echo "[QuickCrypto] Warning: OpenSSL.framework not found at $OPENSSL_FRAMEWORK"
fi
