import type { ConfigPlugin } from 'expo/config-plugins';
import { withDangerousMod } from 'expo/config-plugins';
import fs from 'fs';
import path from 'path';
import type { ConfigProps } from './@types';

export const withSodiumIos: ConfigPlugin<ConfigProps> = config => {
  return withDangerousMod(config, [
    'ios',
    config => {
      const podfilePath = path.join(
        config.modRequest.platformProjectRoot,
        'Podfile',
      );
      let contents = fs.readFileSync(podfilePath, 'utf-8');

      // Check if SODIUM_ENABLED is already set
      if (!contents.includes("ENV['SODIUM_ENABLED']")) {
        // Add it right after the RCT_NEW_ARCH_ENABLED ENV variable
        contents = contents.replace(
          /^(ENV\['RCT_NEW_ARCH_ENABLED'\].*$)/m,
          `$1\nENV['SODIUM_ENABLED'] = '1'`,
        );
        fs.writeFileSync(podfilePath, contents);
      }

      return config;
    },
  ]);
};
