# iOS Setup Guide

## SPM Framework Embedding Required

QuickCrypto uses Swift Package Manager (SPM) dependencies that must be manually embedded in your app bundle:

- **OpenSSL 3.6+** (required) - For ML-DSA post-quantum cryptography support
- **Sodium** (optional) - For XSalsa20 cipher support via libsodium (when `SODIUM_ENABLED=1`)

### Why is this needed?

CocoaPods doesn't automatically embed SPM frameworks into the final app bundle. Without this configuration, you'll encounter runtime errors:

```
dyld: Library not loaded: @rpath/OpenSSL.framework/OpenSSL
```

This is a temporary limitation of mixing CocoaPods + SPM. It will be resolved when React Native fully migrates to SPM (expected 2026).

## Configuration

Add the following to your `ios/Podfile` inside the `post_install` hook:

```ruby
post_install do |installer|
  # ... your existing post_install code (react_native_post_install, etc.) ...

  # Embed SPM frameworks from QuickCrypto
  main_project_path = File.join(installer.sandbox.root.parent, 'YourAppName.xcodeproj')
  main_project = Xcodeproj::Project.open(main_project_path)
  app_target = main_project.targets.find { |t| t.name == 'YourAppName' }

  if app_target
    embed_phase_name = 'Embed SPM Frameworks (QuickCrypto)'
    existing_phase = app_target.shell_script_build_phases.find { |p| p.name == embed_phase_name }

    unless existing_phase
      phase = app_target.new_shell_script_build_phase(embed_phase_name)
      phase.shell_script = <<~SCRIPT
        mkdir -p "${BUILT_PRODUCTS_DIR}/${FRAMEWORKS_FOLDER_PATH}"

        # Embed OpenSSL.framework (required for ML-DSA)
        if [ -d "${BUILT_PRODUCTS_DIR}/OpenSSL.framework" ]; then
          rsync -av --delete "${BUILT_PRODUCTS_DIR}/OpenSSL.framework" "${BUILT_PRODUCTS_DIR}/${FRAMEWORKS_FOLDER_PATH}/"
          if [ -n "${EXPANDED_CODE_SIGN_IDENTITY:-}" ]; then
            /usr/bin/codesign --force --sign "${EXPANDED_CODE_SIGN_IDENTITY}" --preserve-metadata=identifier,entitlements "${BUILT_PRODUCTS_DIR}/${FRAMEWORKS_FOLDER_PATH}/OpenSSL.framework"
          fi
        fi

        # Embed Sodium.framework (optional, if SODIUM_ENABLED=1)
        if [ -d "${BUILT_PRODUCTS_DIR}/Sodium.framework" ]; then
          rsync -av --delete "${BUILT_PRODUCTS_DIR}/Sodium.framework" "${BUILT_PRODUCTS_DIR}/${FRAMEWORKS_FOLDER_PATH}/"
          if [ -n "${EXPANDED_CODE_SIGN_IDENTITY:-}" ]; then
            /usr/bin/codesign --force --sign "${EXPANDED_CODE_SIGN_IDENTITY}" --preserve-metadata=identifier,entitlements "${BUILT_PRODUCTS_DIR}/${FRAMEWORKS_FOLDER_PATH}/Sodium.framework"
          fi
        fi
      SCRIPT

      # Insert before the CocoaPods embed frameworks phase
      embed_pods_phase = app_target.shell_script_build_phases.find { |p| p.name == '[CP] Embed Pods Frameworks' }
      if embed_pods_phase
        app_target.build_phases.move(phase, app_target.build_phases.index(embed_pods_phase))
      end

      main_project.save
    end
  end
end
```

**Important:** Replace `YourAppName` with your actual Xcode target name (usually matches your app name).

## Example

See the [example app's Podfile](../../example/ios/Podfile) for a complete working reference.

## Enabling libsodium (Optional)

To enable XSalsa20 cipher support, set the environment variable before installing pods:

```ruby
# At the top of your Podfile
ENV['SODIUM_ENABLED'] = '1'
```

Then run:

```bash
cd ios && pod install
```

## Troubleshooting

### Error: "Library not loaded: @rpath/OpenSSL.framework/OpenSSL"

This means the SPM frameworks aren't being embedded. Verify:

1. The `post_install` hook is properly configured in your Podfile
2. You're using `use_frameworks! :linkage => :dynamic` (required for SPM dependencies)
3. Run `cd ios && pod install` after modifying the Podfile
4. Clean build folder in Xcode (Cmd+Shift+K) and rebuild

### Dynamic Frameworks Required

QuickCrypto requires dynamic framework linking due to SPM dependencies. Add this to your Podfile:

```ruby
use_frameworks! :linkage => :dynamic
```

## Future

When React Native completes its migration to Swift Package Manager (expected 2026), this manual embedding step will no longer be necessary. SPM packages will be properly integrated by default.
