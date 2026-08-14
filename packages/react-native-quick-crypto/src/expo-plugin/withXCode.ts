import type { ConfigPlugin } from 'expo/config-plugins';
import type { ConfigProps } from './@types';
import {
  IOSConfig,
  withDangerousMod,
  withPodfileProperties,
  withXcodeProject,
} from 'expo/config-plugins';
import fs from 'fs';
import path from 'path';

const MIN_IOS_DEPLOYMENT_TARGET = '16.4';
const MIN_PARTS = MIN_IOS_DEPLOYMENT_TARGET.split('.').map(Number);

/**
 * True when `version` is absent or below our minimum, i.e. we should raise it.
 * Compared component-wise: '16.10' and '16.4.1' are both above '16.4'.
 */
export function needsRaising(version: string | undefined): boolean {
  if (!version) return true;

  const parts = version.split('.').map(Number);
  if (!parts.every(Number.isFinite)) {
    console.warn(
      `[react-native-quick-crypto] leaving unparseable iOS deployment target "${version}" alone`,
    );
    return false;
  }

  for (let i = 0; i < Math.max(parts.length, MIN_PARTS.length); i++) {
    const diff = (parts[i] ?? 0) - (MIN_PARTS[i] ?? 0);
    if (diff !== 0) return diff < 0;
  }
  return false;
}

const POST_INSTALL_PATCH = `    # react-native-quick-crypto: floor the pods' deployment target, never lower it
    # https://github.com/mrousavy/nitro/issues/422#issuecomment-2545988256
    installer.pods_project.targets.each do |target|
      target.build_configurations.each do |config|
        current = config.build_settings['IPHONEOS_DEPLOYMENT_TARGET'].to_s
        if !Gem::Version.correct?(current) ||
           Gem::Version.new(current) < Gem::Version.new('${MIN_IOS_DEPLOYMENT_TARGET}')
          config.build_settings['IPHONEOS_DEPLOYMENT_TARGET'] = '${MIN_IOS_DEPLOYMENT_TARGET}'
        end
      end
    end`;

/**
 * Fallback for Podfiles whose post_install doesn't already pin a deployment
 * target. No-op when one is already pinned - that's the app's call, not ours.
 */
export function patchPodfile(contents: string): string {
  const alreadyPinned =
    /\.build_settings\s*\[\s*['"]IPHONEOS_DEPLOYMENT_TARGET['"]\s*\]\s*=/.test(
      contents,
    );
  if (alreadyPinned) return contents;

  const patched = contents.replace(
    /(post_install\s+do\s+\|installer\|[\s\S]*?)(\r?\n\s\send\s*)$/m,
    `$1\n\n${POST_INSTALL_PATCH}\n$2`,
  );
  if (patched === contents) {
    console.warn(
      '[react-native-quick-crypto] no post_install block found in the Podfile; skipping the iOS deployment target floor',
    );
  }
  return patched;
}

/**
 *  Workaround for some jank XCode releases that break React Native native modules
 *
 *  see: https://github.com/mrousavy/nitro/issues/422#issuecomment-2545988256
 *
 *  Raises the iOS deployment target to our minimum wherever it is lower. Reads
 *  the value at mod time rather than from static `plugins` config, so it floors
 *  apps that set a higher target by any means and never lowers one. (#1066)
 */
export const withXCode: ConfigPlugin<ConfigProps> = config => {
  // what the generated Podfile reads for `platform :ios`
  config = withPodfileProperties(config, podfileConfig => {
    if (needsRaising(podfileConfig.modResults['ios.deploymentTarget'])) {
      podfileConfig.modResults['ios.deploymentTarget'] =
        MIN_IOS_DEPLOYMENT_TARGET;
    }
    return podfileConfig;
  });

  // the app target in the generated Xcode project
  config = withXcodeProject(config, xcodeConfig => {
    const { Target, XcodeUtils } = IOSConfig;
    const listIds = Target.getNativeTargets(xcodeConfig.modResults)
      .filter(([, target]) =>
        Target.isTargetOfType(target, Target.TargetType.APPLICATION),
      )
      .map(([, target]) => target.buildConfigurationList);

    for (const listId of listIds) {
      const configurations = XcodeUtils.getBuildConfigurationsForListId(
        xcodeConfig.modResults,
        listId,
      );
      for (const [, { buildSettings }] of configurations) {
        // only floor an explicit target - writing one that was inherited from
        // the project level could itself be a downgrade
        const current = buildSettings?.IPHONEOS_DEPLOYMENT_TARGET;
        if (current && needsRaising(String(current))) {
          buildSettings.IPHONEOS_DEPLOYMENT_TARGET = MIN_IOS_DEPLOYMENT_TARGET;
        }
      }
    }
    return xcodeConfig;
  });

  // pods that don't inherit the platform from the Podfile
  config = withDangerousMod(config, [
    'ios',
    modConfig => {
      const podfilePath = path.join(
        modConfig.modRequest.platformProjectRoot,
        'Podfile',
      );
      fs.writeFileSync(
        podfilePath,
        patchPodfile(fs.readFileSync(podfilePath, 'utf-8')),
      );
      return modConfig;
    },
  ]);

  return config;
};
