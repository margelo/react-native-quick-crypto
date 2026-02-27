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

      if (!contents.includes("ENV['SODIUM_ENABLED']")) {
        contents = `ENV['SODIUM_ENABLED'] = '1'\n${contents}`;
        fs.writeFileSync(podfilePath, contents);
      }

      return config;
    },
  ]);
};
