// polyfills
import { install } from 'react-native-quick-crypto';
install();

// mocha things
global.process.cwd = () => 'sxsx';

// readable-stream
global.process.version = 'v22.0.0';
// global.process.env = { NODE_ENV: 'production' };
// global.location = {};

import { AppRegistry } from 'react-native';
import App from './src/App';
import { name as appName } from './app.json';

AppRegistry.registerComponent(appName, () => App);
