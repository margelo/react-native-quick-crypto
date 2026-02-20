# Fix for Issue #881: OpenSSL.xcframework Conflicting Names

## Problem

When users have multiple libraries that vendor `OpenSSL.xcframework`, CocoaPods fails with:
```
The 'Pods-MyApp' target has frameworks with conflicting names: openssl.xcframework
```

This occurs because react-native-quick-crypto and other libraries (realm, web3auth, etc.) both vendor frameworks with the same name.

## Solution

Rename the vendored framework from `OpenSSL.xcframework` to `QuickCryptoOpenSSL.xcframework`. This makes the framework name unique while keeping the inner OpenSSL library unchanged.

**Why this works:**
- CocoaPods conflicts on the outer xcframework directory name
- The inner `OpenSSL.framework` and headers remain unchanged
- C++ code uses `#include <openssl/evp.h>` style includes (not affected)
- Header search paths continue to work

**Caveat:** This fix allows both frameworks to be included, which means duplicate OpenSSL binaries in the app bundle (increased app size by ~15-20MB). Users should verify they actually need both libraries.

## Files to Modify

### 1. `packages/react-native-quick-crypto/QuickCrypto.podspec`

**Changes:**
- Add constant for new framework name: `QuickCryptoOpenSSL.xcframework`
- Update inline download section to rename after extraction
- Update both `prepare_command` blocks (with/without sodium)
- Update `s.vendored_frameworks` reference

### 2. `packages/react-native-quick-crypto/.gitignore`

**Changes:**
- Change `OpenSSL.xcframework/` to `QuickCryptoOpenSSL.xcframework/`

### 3. `.docs/troubleshooting.md`

**Changes:**
- Add section documenting the rename for users upgrading
- Note that users should clean Pods directory after upgrade

## Implementation Details

### Podspec Changes

```ruby
# New constant at top of OpenSSL section
openssl_xcframework_name = "QuickCryptoOpenSSL.xcframework"

# Update directory references
openssl_dir = File.join(__dir__, openssl_xcframework_name)

# After unzip, rename the framework
FileUtils.mv("OpenSSL.xcframework", openssl_xcframework_name)

# Update vendored_frameworks
s.vendored_frameworks = "QuickCryptoOpenSSL.xcframework"
```

### prepare_command Changes

```bash
if [ ! -d "QuickCryptoOpenSSL.xcframework" ]; then
  curl -L -o OpenSSL.xcframework.zip #{openssl_url}
  unzip -o OpenSSL.xcframework.zip
  mv OpenSSL.xcframework QuickCryptoOpenSSL.xcframework
  rm -f OpenSSL.xcframework.zip
fi
```

## Verification

1. **Build test**: Clean Pods directory, run `pod install`, build example app
2. **Conflict reproduction**: Create test project with both `react-native-quick-crypto` and the conflicting library
3. **Functionality test**: Run crypto tests in example app to verify OpenSSL still works
4. **CI**: Ensure CI builds pass (may need cache invalidation)

## Risk Assessment

**Low risk** - Only the container name changes, not the OpenSSL library itself:
- All C++ code unchanged
- Headers resolve identically
- Module structure intact

**Migration note**: Users with cached `OpenSSL.xcframework` should run:
```bash
cd ios && rm -rf Pods Podfile.lock && pod install
```

## Status

**Waiting for feedback** - Asked issue reporter to identify which library is causing the conflict before implementing.
