#
# quickcrypto_spm_fix.rb
# Fixes OpenSSL.framework code signing for physical iOS devices
# See: https://github.com/margelo/react-native-quick-crypto/issues/857
#
# REQUIRED: Add this to your ios/Podfile:
#
#   require_relative '../node_modules/react-native-quick-crypto/scripts/quickcrypto_spm_fix'
#
#   # ... target block ...
#
#   post_install do |installer|
#     # ... other post_install code (like react_native_post_install) ...
#
#     # Fix QuickCrypto SPM framework signing for physical devices
#     quickcrypto_fix_spm_signing(installer)
#   end
#
# Options:
#   quickcrypto_fix_spm_signing(installer, app_target_name: 'MyAppName')
#   - Use app_target_name if you have multiple targets or non-standard naming
#

def quickcrypto_fix_spm_signing(installer, app_target_name: nil)
  # Find the main project (user's app project, not Pods project)
  main_project_path = File.join(installer.sandbox.root.parent, "#{installer.sandbox.root.parent.basename}.xcodeproj")

  # If the default path doesn't exist, try to find any .xcodeproj
  unless File.exist?(main_project_path)
    xcodeproj_files = Dir.glob(File.join(installer.sandbox.root.parent, "*.xcodeproj"))
    main_project_path = xcodeproj_files.first if xcodeproj_files.any?
  end

  unless main_project_path && File.exist?(main_project_path)
    Pod::UI.warn "[QuickCrypto] Could not find main Xcode project. SPM framework signing must be configured manually."
    Pod::UI.warn "[QuickCrypto] See: https://github.com/margelo/react-native-quick-crypto/issues/857"
    return
  end

  main_project = Xcodeproj::Project.open(main_project_path)

  # Find the app target
  app_target = if app_target_name
    main_project.targets.find { |t| t.name == app_target_name }
  else
    # Find first application target
    main_project.targets.find { |t| t.product_type == "com.apple.product-type.application" }
  end

  unless app_target
    Pod::UI.warn "[QuickCrypto] Could not find app target. SPM framework signing must be configured manually."
    return
  end

  Pod::UI.puts "[QuickCrypto] Configuring SPM framework signing for target: #{app_target.name}"

  # Remove old/duplicate SPM embed phases
  old_phase_names = [
    'Embed SPM Frameworks (QuickCrypto)',
    'Embed SPM Frameworks (OpenSSL)',
    '[CP-User] Embed OpenSSL Framework',
    '[CP-User] [CP-User] Embed OpenSSL Framework',
    '[QuickCrypto] Embed & Sign SPM Frameworks'
  ]

  phases_to_remove = app_target.shell_script_build_phases.select { |p| old_phase_names.include?(p.name) }
  phases_to_remove.each do |phase|
    app_target.build_phases.delete(phase)
    Pod::UI.puts "[QuickCrypto] Removed old build phase: #{phase.name}"
  end

  # Create new consolidated build phase
  embed_phase_name = '[QuickCrypto] Embed & Sign SPM Frameworks'

  phase = app_target.new_shell_script_build_phase(embed_phase_name)
  phase.shell_script = <<~'SCRIPT'
    set -euo pipefail

    # Embed and sign SPM frameworks (OpenSSL) from QuickCrypto
    # This phase MUST run LAST, after all other framework embedding
    # See: https://github.com/margelo/react-native-quick-crypto/issues/857

    FRAMEWORKS_DIR="${BUILT_PRODUCTS_DIR}/${FRAMEWORKS_FOLDER_PATH}"
    mkdir -p "$FRAMEWORKS_DIR"

    sign_framework() {
      local framework_path="$1"
      local framework_name=$(basename "$framework_path")

      if [ ! -d "$framework_path" ]; then
        echo "warning: $framework_name not found at $framework_path, skipping"
        return 0
      fi

      echo "[QuickCrypto] Processing $framework_name..."

      # Copy to app bundle
      rsync -av --delete "$framework_path" "$FRAMEWORKS_DIR/"

      local dest_framework="$FRAMEWORKS_DIR/$framework_name"

      # Sign if required (physical device builds only)
      if [ "${CODE_SIGNING_REQUIRED:-NO}" = "YES" ] && [ -n "${EXPANDED_CODE_SIGN_IDENTITY:-}" ]; then
        echo "[QuickCrypto] Signing $framework_name with identity: ${EXPANDED_CODE_SIGN_IDENTITY}"

        # Make framework writable (rsync preserves read-only from source)
        chmod -R u+w "$dest_framework"

        # Strip existing signature and re-sign with app's identity
        # This is required for pre-signed xcframeworks from SPM
        /usr/bin/codesign --force --deep --sign "${EXPANDED_CODE_SIGN_IDENTITY}" \
          --timestamp=none \
          "$dest_framework"

        echo "[QuickCrypto] Successfully signed $framework_name"
      else
        echo "[QuickCrypto] Code signing not required (simulator build)"
      fi
    }

    # Sign OpenSSL.framework from SPM
    sign_framework "${BUILT_PRODUCTS_DIR}/OpenSSL.framework"

    echo "[QuickCrypto] SPM framework embedding complete"
  SCRIPT

  # Move to the very end of build phases (after all CocoaPods phases)
  app_target.build_phases.move(phase, app_target.build_phases.count - 1)

  main_project.save
  Pod::UI.puts "[QuickCrypto] Added '#{embed_phase_name}' build phase (placed last for proper signing)"
end
