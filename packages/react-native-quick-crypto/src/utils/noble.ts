import type { Hex } from './types';

/**
 * Takes hex string or Uint8Array, converts to Uint8Array.
 * Validates output length.
 * Will throw error for other types.
 * @param title descriptive title for an error e.g. 'private key'
 * @param hex hex string or Uint8Array
 * @param expectedLength optional, will compare to result array's length
 * @returns
 */
export function ensureBytes(
  title: string,
  hex: Hex,
  expectedLength?: number,
): Uint8Array {
  let res: Uint8Array;
  if (typeof hex === 'string') {
    try {
      res = hexToBytes(hex);
    } catch (e) {
      throw new Error(title + ' must be hex string or Uint8Array, cause: ' + e);
    }
  } else if (isBytes(hex)) {
    // Uint8Array.from() instead of hash.slice() because node.js Buffer
    // is instance of Uint8Array, and its slice() creates **mutable** copy
    res = Uint8Array.from(hex);
  } else {
    throw new Error(title + ' must be hex string or Uint8Array');
  }
  const len = res.length;
  if (typeof expectedLength === 'number' && len !== expectedLength)
    throw new Error(
      title + ' of length ' + expectedLength + ' expected, got ' + len,
    );
  return res;
}

/** Checks if something is Uint8Array. Be careful: nodejs Buffer will return true. */
export function isBytes(a: unknown): a is Uint8Array {
  return (
    a instanceof Uint8Array ||
    (ArrayBuffer.isView(a) && a.constructor.name === 'Uint8Array')
  );
}

// We use optimized technique to convert hex string to byte array
const asciis = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 } as const;
function asciiToBase16(ch: number): number | undefined {
  if (ch >= asciis._0 && ch <= asciis._9) return ch - asciis._0; // '2' => 50-48
  if (ch >= asciis.A && ch <= asciis.F) return ch - (asciis.A - 10); // 'B' => 66-(65-10)
  if (ch >= asciis.a && ch <= asciis.f) return ch - (asciis.a - 10); // 'b' => 98-(97-10)
  return;
}

/**
 * Convert hex string to byte array. Uses built-in function, when available.
 * @example hexToBytes('cafe0123') // Uint8Array.from([0xca, 0xfe, 0x01, 0x23])
 */
export function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string')
    throw new Error('hex string expected, got ' + typeof hex);
  // @ts-expect-error Uint8Array.fromHex
  if (hasHexBuiltin) return Uint8Array.fromHex(hex);
  const hl = hex.length;
  const al = hl / 2;
  if (hl % 2)
    throw new Error('hex string expected, got unpadded hex of length ' + hl);
  const array = new Uint8Array(al);
  for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
    const n1 = asciiToBase16(hex.charCodeAt(hi));
    const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
    if (n1 === undefined || n2 === undefined) {
      const char = hex.substring(hi, hi + 2);
      throw new Error(
        'hex string expected, got non-hex character "' +
          char +
          '" at index ' +
          hi,
      );
    }
    array[ai] = n1 * 16 + n2; // multiply first octet, e.g. 'a3' => 10*16+3 => 160 + 3 => 163
  }
  return array;
}
