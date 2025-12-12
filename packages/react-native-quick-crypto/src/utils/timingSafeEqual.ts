import { NitroModules } from 'react-native-nitro-modules';
import type { Utils } from '../specs/utils.nitro';
import type { ABV } from './types';
import { abvToArrayBuffer } from './conversion';

let utils: Utils;
function getNative(): Utils {
  if (utils == null) {
    utils = NitroModules.createHybridObject<Utils>('Utils');
  }
  return utils;
}

export function timingSafeEqual(a: ABV, b: ABV): boolean {
  const bufA = abvToArrayBuffer(a);
  const bufB = abvToArrayBuffer(b);

  if (bufA.byteLength !== bufB.byteLength) {
    throw new RangeError('Input buffers must have the same byte length');
  }

  return getNative().timingSafeEqual(bufA, bufB);
}
