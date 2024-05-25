global.process.cwd = () => 'sxsx';
global.process.env = { NODE_ENV: 'production' };
global.location = {};
global.Buffer = require('buffer').Buffer;

import { AppRegistry } from 'react-native';
import App from './src/App';
import { name as appName } from './app.json';

AppRegistry.registerComponent(appName, () => App);


