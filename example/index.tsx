const crypto = require('crypto');
crypto.publicEncrypt =
  require('react-native-quick-crypto').default.publicEncrypt;
crypto.privateDecrypt =
  require('react-native-quick-crypto').default.privateDecrypt;
crypto.generateKeyPair =
  require('react-native-quick-crypto').default.generateKeyPair;
import { Buffer } from 'buffer';
global.Buffer = Buffer;
// @ts-ignore
global.process = {
  cwd: () => 'sxsx',
  env: { NODE_ENV: 'production' },
  nextTick: () => {
    return null;
  },
};
// @ts-ignore
global.location = {};

import { AppRegistry } from 'react-native';
import App from './src/App';
import { name as appName } from './app.json';

AppRegistry.registerComponent(appName, () => App);
