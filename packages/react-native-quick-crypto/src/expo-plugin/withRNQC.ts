import { createRunOncePlugin } from 'expo/config-plugins';
import type { ConfigPlugin } from 'expo/config-plugins';
import type { ConfigProps } from './@types';
import { withSodiumIos } from './withSodiumIos';
import { withSodiumAndroid } from './withSodiumAndroid';
import { withXCode } from './withXCode';

const withRNQCInternal: ConfigPlugin<ConfigProps> = (config, props = {}) => {
  // add XCode workarounds for some 16.x releases that are not RN-friendly
  config = withXCode(config, props);

  // enable libsodium algorithms
  if (props.sodiumEnabled) {
    config = withSodiumIos(config, props);
    config = withSodiumAndroid(config, props);
  }

  return config;
};

export function createRNQCPlugin(name: string, version: string) {
  return createRunOncePlugin(withRNQCInternal, name, version);
}
