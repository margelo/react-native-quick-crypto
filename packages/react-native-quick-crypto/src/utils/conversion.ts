import { Buffer } from '@craftzdog/react-native-buffer';
import type { ArrayBufferView } from './types';

export const abvToArrayBuffer = (buffer: ArrayBufferView) => {
  if (Buffer.isBuffer(buffer)) {
    return buffer.buffer;
  }
  if (ArrayBuffer.isView(buffer)) {
    return buffer.buffer;
  }
  return buffer;
};

export function ab2str(buf: ArrayBuffer, encoding: string = 'hex') {
  return Buffer.from(buf).toString(encoding);
}
