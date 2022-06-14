import { Buffer } from 'buffer';
global.Buffer = Buffer;
// @ts-ignore
global.process = {
  cwd: () => 'sxsx',
  env: { NODE_ENV: 'production' },
};
// @ts-ignore
global.location = {};

import { AppRegistry } from 'react-native';
import App from './src/App';
import { name as appName } from './app.json';

AppRegistry.registerComponent(appName, () => App);
