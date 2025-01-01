import { AppRegistry } from 'react-native';
import App from './src/App';
import { name as appName } from './app.json';
import { install } from 'react-native-quick-crypto';

const global = globalThis;
install();
global.process.cwd = () => 'sxsx';
global.process.env = { NODE_ENV: 'production' };
global.location = {};

AppRegistry.registerComponent(appName, () => App);
