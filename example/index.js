const crypto = require('crypto');
crypto.publicEncrypt =
  require('react-native-quick-crypto').default.publicEncrypt;
crypto.privateDecrypt =
  require('react-native-quick-crypto').default.privateDecrypt;
crypto.generateKeyPair =
  require('react-native-quick-crypto').default.generateKeyPair;
crypto.createVerify = 
  require('react-native-quick-crypto').default.createVerify;
crypto.createSign =
  require('react-native-quick-crypto').default.createSign;
import { Buffer } from 'buffer';
global.Buffer = Buffer;
global.process.cwd = () => 'sxsx';
global.process.env = { NODE_ENV: 'production' };
global.location = {};

import { AppRegistry } from 'react-native';
import App from './src/App';
import { name as appName } from './app.json';

AppRegistry.registerComponent(appName, () => App);
