# iOS Setup Guide

## SPM Framework Signing (Physical Devices)

QuickCrypto uses OpenSSL via Swift Package Manager (SPM). On **physical iOS devices**, SPM frameworks require additional configuration to be properly embedded and code-signed in your app bundle.

> **Simulator builds work without this configuration.** This is only required for physical device deployment.

### Quick Setup

Add to your `ios/Podfile`:

```ruby
# At the top of your Podfile
require_relative '../node_modules/react-native-quick-crypto/scripts/quickcrypto_spm_fix'

target 'YourAppName' do
  # ... your pods ...

  post_install do |installer|
    react_native_post_install(installer)  # if you have this
    
    # Fix QuickCrypto SPM framework signing for physical devices
    quickcrypto_fix_spm_signing(installer)
  end
end
```

Then run:

```bash
cd ios && pod install
```

### Why is this needed?

When you try to install on a physical device without this fix, you'll see:

```
Failed to verify code signature of .../OpenSSL.framework : 0xe8008015
```

This happens because:
1. OpenSSL is distributed as a pre-built, pre-signed xcframework via SPM
2. CocoaPods' `spm_dependency` adds it to the Pods project but doesn't embed it in your app
3. The framework must be re-signed with your app's code signing identity

This is a known limitation of mixing CocoaPods + SPM. See [issue #857](https://github.com/margelo/react-native-quick-crypto/issues/857).

### Multiple Targets

If you have multiple app targets, specify which one:

```ruby
quickcrypto_fix_spm_signing(installer, app_target_name: 'YourSpecificTarget')
```

## Enabling libsodium (Optional)

For XSalsa20 cipher support, set the environment variable before your target:

```ruby
ENV['SODIUM_ENABLED'] = '1'

target 'YourAppName' do
  # ...
end
```

## Troubleshooting

### Error: `0xe8008015` on physical device

This is the code signing error. Make sure you've added `quickcrypto_fix_spm_signing(installer)` to your Podfile's `post_install` hook and run `pod install`.

### Error: "Library not loaded: @rpath/OpenSSL.framework"

Same fix - the `quickcrypto_fix_spm_signing` function handles both embedding and signing.

### Build still fails after adding the fix

1. Clean build: `Cmd+Shift+K` in Xcode
2. Delete derived data: `rm -rf ~/Library/Developer/Xcode/DerivedData`
3. Run `pod install` again
4. Rebuild

### "Could not find main Xcode project" warning

The helper script couldn't find your `.xcodeproj` file. Use the `app_target_name` parameter or check that your project structure is standard.

## The SPM Situation

Yes, this is unfortunate. CocoaPods is being deprecated, SPM is supposed to be the future, but SPM's handling of binary frameworks with CocoaPods is broken. The `spm_dependency` bridge in React Native doesn't properly handle framework embedding and code signing.

This workaround will be unnecessary when React Native fully migrates to SPM (timeline unclear).
