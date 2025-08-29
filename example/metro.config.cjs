const { getDefaultConfig, mergeConfig } = require('@react-native/metro-config')
const path = require('path')
const blacklist = require('metro-config/src/defaults/exclusionList')
const escape = require('escape-string-regexp')
const pack = require('../package.json')

const root = path.resolve(__dirname, '..')
const peerModules = Object.keys({ ...pack.peerDependencies })

/**
 * Metro configuration
 * https://reactnative.dev/docs/metro
 *
 * @type {import('@react-native/metro-config').MetroConfig}
 */
const config = {
  watchFolders: [root],

  // We need to make sure that only one version is loaded for peerDependencies
  // So we blacklist them at the root, and alias them to the versions in example's node_modules
  resolver: {
    blacklistRE: blacklist(
      peerModules.map(
        (m) =>
          new RegExp(`^${escape(path.join(root, 'node_modules', m))}\\/.*$`)
      )
    ),

    extraNodeModules: {
      ...peerModules.reduce((acc, name) => {
        acc[name] = path.join(__dirname, 'node_modules', name)
        return acc
      }, {}),
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
}

module.exports = mergeConfig(getDefaultConfig(__dirname), config)
