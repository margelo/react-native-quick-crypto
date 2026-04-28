import { NitroModules } from 'react-native-nitro-modules';
import type { Utils } from '../specs/utils.nitro';
import type { ABV } from './types';
import { binaryLikeToArrayBuffer } from './conversion';

let utils: Utils;
function getNative(): Utils {
  if (utils == null) {
    utils = NitroModules.createHybridObject<Utils>('Utils');
  }
  return utils;
}

export function timingSafeEqual(a: ABV, b: ABV): boolean {
  // Use binaryLikeToArrayBuffer (not abvToArrayBuffer) so that TypedArray /
  // Buffer views are sliced to their `byteOffset`/`byteLength` window. The
  // zero-copy `abvToArrayBuffer` returns the entire backing buffer, which
  // would (a) compare unrelated bytes and (b) silently fail the byte-length
  // check for any view smaller than its backing.
  const bufA = binaryLikeToArrayBuffer(a);
  const bufB = binaryLikeToArrayBuffer(b);

  if (bufA.byteLength !== bufB.byteLength) {
    throw new RangeError('Input buffers must have the same byte length');
  }

  return getNative().timingSafeEqual(bufA, bufB);
}
