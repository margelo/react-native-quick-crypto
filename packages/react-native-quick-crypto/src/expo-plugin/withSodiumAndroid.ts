import type { ConfigPlugin } from 'expo/config-plugins';
import { withGradleProperties } from 'expo/config-plugins';
import type { ConfigProps } from './@types';

export const withSodiumAndroid: ConfigPlugin<ConfigProps> = config => {
  return withGradleProperties(config, config => {
    config.modResults = config.modResults || [];

    // Check if the property already exists
    const existingProperty = config.modResults.find(
      item => item.type === 'property' && item.key === 'sodiumEnabled',
    );

    if (!existingProperty) {
      config.modResults.push({
        type: 'property',
        key: 'sodiumEnabled',
        value: 'true',
      });
    }

    return config;
  });
};
