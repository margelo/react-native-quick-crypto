const { getDefaultConfig, mergeConfig } = require('@react-native/metro-config');
const path = require('path');

const root = path.resolve(__dirname, '..');
const packagesDir = path.join(root, 'packages');

/**
 * Metro configuration
 * https://reactnative.dev/docs/metro
 *
 * @type {import('@react-native/metro-config').MetroConfig}
 */
const config = {
  watchFolders: [root],

  resolver: {
    nodeModulesPaths: [
      path.join(__dirname, 'node_modules'),
      path.join(root, 'node_modules'),
      packagesDir,
    ],
    extraNodeModules: {
      stream: require.resolve('readable-stream'),
    },
  },

  transformer: {
    getTransformOptions: async () => ({
      transform: {
        experimentalImportSupport: false,
        inlineRequires: true,
      },
    }),
  },
};

module.exports = mergeConfig(getDefaultConfig(__dirname), config);
