const path = require('path');
const pak = require('../../packages/react-native-quick-crypto/package.json');

module.exports = {
  presets: ['module:@react-native/babel-preset'],
  plugins: [
    ['@babel/plugin-transform-class-static-block'],
    [
      'module-resolver',
      {
        extensions: ['.tsx', '.ts', '.js', '.json'],
        alias: {
          crypto: 'react-native-quick-crypto',
          stream: 'readable-stream',
          buffer: '@craftzdog/react-native-buffer',
        },
      },
    ],
  ],
};
