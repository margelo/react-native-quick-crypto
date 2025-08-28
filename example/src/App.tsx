import * as React from 'react';
import { Root } from './navigators/Root';
import { LogBox } from 'react-native';

export default function App() {
  return <Root />;
}

LogBox.ignoreLogs(['Open debugger to view warnings']);
