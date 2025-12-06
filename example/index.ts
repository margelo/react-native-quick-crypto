// polyfills
import { install } from 'react-native-quick-crypto';
install();

// TextEncoder/TextDecoder polyfill (required for jose)
import FastEncoder from 'react-native-fast-encoder';
class TextEncoderPolyfill {
  encode(input: string): Uint8Array {
    const encoder = new FastEncoder();
    return encoder.encode(input);
  }
}
class TextDecoderPolyfill {
  private encoder: FastEncoder;
  constructor(_encoding: string = 'utf-8') {
    this.encoder = new FastEncoder(_encoding);
  }
  decode(input: Uint8Array): string {
    return this.encoder.decode(input);
  }
}
global.TextEncoder = TextEncoderPolyfill as unknown as typeof TextEncoder;
global.TextDecoder = TextDecoderPolyfill as unknown as typeof TextDecoder;

// structuredClone polyfill (required for jose)
if (typeof global.structuredClone === 'undefined') {
  global.structuredClone = <T>(obj: T): T => JSON.parse(JSON.stringify(obj));
}

// event-target-shim
import 'event-target-polyfill';

// readable-stream
if (typeof global.process !== 'undefined') {
  const descriptor = Object.getOwnPropertyDescriptor(global.process, 'version');
  if (!descriptor || descriptor.writable || descriptor.configurable) {
    try {
      Object.defineProperty(global.process, 'version', {
        value: 'v22.0.0',
        writable: true,
        enumerable: true,
        configurable: true,
      });
    } catch (e) {
      console.warn('Failed to define process.version:', e);
    }
  }
} else {
  // @ts-expect-error - process is not defined
  global.process = { version: 'v22.0.0' };
}

import { AppRegistry } from 'react-native';
import App from './src/App';
import { name as appName } from './app.json';

AppRegistry.registerComponent(appName, () => App);
