import type { Buffer } from "@craftzdog/react-native-buffer";

export function isBuffer(buf: Buffer) {
  return buf instanceof Buffer || buf?.constructor?.name === 'Buffer';
}

export function toArrayBuffer(buf: Buffer) {
  if (buf?.buffer?.slice) {
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  }
  const ab = new ArrayBuffer(buf.length);
  const view = new Uint8Array(ab);
  for (let i = 0; i < buf.length; ++i) {
    view[i] = buf[i];
  }
  return ab;
}
