const path = require('path');
const pak = require('../package.json');

module.exports = {
  presets: ['module:metro-react-native-babel-preset'],
  plugins: [
    [
      'module-resolver',
      {
        extensions: ['.js', '.ts', '.json', '.jsx', '.tsx'],
        alias: {
          [pak.name]: path.join(__dirname, '..', pak.source),
          crypto: 'crypto-browserify',
          stream: 'stream-browserify',
        },
      },
    ],
  ],
};
