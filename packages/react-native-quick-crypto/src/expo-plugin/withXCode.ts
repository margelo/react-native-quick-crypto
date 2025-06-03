import type { ConfigPlugin } from 'expo/config-plugins';
import type { ConfigProps } from './@types';
import { withBuildProperties } from 'expo-build-properties';
import { withDangerousMod } from 'expo/config-plugins';
import fs from 'fs';
import path from 'path';

/**
 *  Workaround for some jank XCode releases that break React Native native modules
 *
 *  see: https://github.com/mrousavy/nitro/issues/422#issuecomment-2545988256
 */
export const withXCode: ConfigPlugin<ConfigProps> = config => {
  // Use expo-build-properties to bump iOS deployment target
  config = withBuildProperties(config, { ios: { deploymentTarget: '16.0' } });
  // Patch the generated Podfile fallback to ensure platform is always 16.0
  config = withDangerousMod(config, [
    'ios',
    modConfig => {
      const podfilePath = path.join(
        modConfig.modRequest.platformProjectRoot,
        'Podfile',
      );
      let contents = fs.readFileSync(podfilePath, 'utf-8');

      // Check if the IPHONEOS_DEPLOYMENT_TARGET setting is already present
      // We search for the key being assigned, e.g., config.build_settings['IPHONEOS_DEPLOYMENT_TARGET'] =
      const deploymentTargetSettingExists =
        /\.build_settings\s*\[\s*['"]IPHONEOS_DEPLOYMENT_TARGET['"]\s*\]\s*=/.test(
          contents,
        );

      if (!deploymentTargetSettingExists) {
        // IPHONEOS_DEPLOYMENT_TARGET setting not found, proceed to add it.
        contents = contents.replace(
          /(post_install\s+do\s+\|installer\|[\s\S]*?)(\r?\n\s\send\s*)$/m,
          `$1

    # Expo Build Properties: force deployment target
    # https://github.com/mrousavy/nitro/issues/422#issuecomment-2545988256
    installer.pods_project.targets.each do |target|
      target.build_configurations.each do |config|
        config.build_settings['IPHONEOS_DEPLOYMENT_TARGET'] = '16.0'
      end
    end
$2`,
        );
      }

      fs.writeFileSync(podfilePath, contents);
      return modConfig;
    },
  ]);
  return config;
};
