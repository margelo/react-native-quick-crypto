import { Buffer as SBuffer } from 'safe-buffer';
import type { BinaryLike, BufferLike, JWK, KeyUsage } from './types';
import { lazyDOMException } from './errors';

// The maximum buffer size that we'll support in the WebCrypto impl
const kMaxBufferLength = 2 ** 31 - 1;

export function validateFunction(f: unknown): boolean {
  return f !== null && typeof f === 'function';
}

export function isStringOrBuffer(val: unknown): val is string | ArrayBuffer {
  return (
    typeof val === 'string' ||
    ArrayBuffer.isView(val) ||
    val instanceof ArrayBuffer
  );
}

export function validateObject<T>(
  value: unknown,
  name: string,
  options?: {
    allowArray: boolean;
    allowFunction: boolean;
    nullable: boolean;
  } | null,
): value is T {
  const useDefaultOptions = options == null;
  const allowArray = useDefaultOptions ? false : options.allowArray;
  const allowFunction = useDefaultOptions ? false : options.allowFunction;
  const nullable = useDefaultOptions ? false : options.nullable;
  if (
    (!nullable && value === null) ||
    (!allowArray && Array.isArray(value)) ||
    (typeof value !== 'object' &&
      (!allowFunction || typeof value !== 'function'))
  ) {
    throw new Error(`${name} is not a valid object ${value}`);
  }
  return true;
}

export const validateMaxBufferLength = (
  data: BinaryLike | BufferLike,
  name: string,
): void => {
  const length =
    typeof data === 'string' || data instanceof SBuffer
      ? data.length
      : data.byteLength;
  if (length > kMaxBufferLength) {
    throw lazyDOMException(
      `${name} must be less than ${kMaxBufferLength + 1} bits`,
      'OperationError',
    );
  }
};

// Returns the intersection of `usageSet` and the spread `usages`, preserving
// the spread order. Dedup and canonical ordering are not performed here —
// the `CryptoKey` constructor runs `getSortedUsages` on every input.
export const getUsagesUnion = (usageSet: KeyUsage[], ...usages: KeyUsage[]) => {
  const newset: KeyUsage[] = [];
  for (let n = 0; n < usages.length; n++) {
    if (!usages[n] || usages[n] === undefined) continue;
    if (usageSet.includes(usages[n] as KeyUsage))
      newset.push(usages[n] as KeyUsage);
  }
  return newset;
};

const kCanonicalUsageOrder: readonly KeyUsage[] = [
  'encrypt',
  'decrypt',
  'sign',
  'verify',
  'deriveKey',
  'deriveBits',
  'wrapKey',
  'unwrapKey',
  'encapsulateKey',
  'encapsulateBits',
  'decapsulateKey',
  'decapsulateBits',
];

export function getSortedUsages(usages: KeyUsage[]): KeyUsage[] {
  const set = new Set<KeyUsage>(usages);
  return kCanonicalUsageOrder.filter(usage => set.has(usage));
}

const kKeyOps: {
  [key in KeyUsage]: number;
} = {
  sign: 1,
  verify: 2,
  encrypt: 3,
  decrypt: 4,
  wrapKey: 5,
  unwrapKey: 6,
  deriveKey: 7,
  deriveBits: 8,
  encapsulateBits: 9,
  decapsulateBits: 10,
  encapsulateKey: 11,
  decapsulateKey: 12,
};

export const validateKeyOps = (
  keyOps: KeyUsage[] | undefined,
  usagesSet: KeyUsage[],
) => {
  if (keyOps === undefined) return;
  if (!Array.isArray(keyOps)) {
    throw lazyDOMException('keyData.key_ops', 'InvalidArgument');
  }
  let flags = 0;
  for (let n = 0; n < keyOps.length; n++) {
    const op: KeyUsage = keyOps[n] as KeyUsage;
    const op_flag = kKeyOps[op];
    // Skipping unknown key ops
    if (op_flag === undefined) continue;
    // Have we seen it already? if so, error
    if (flags & (1 << op_flag))
      throw lazyDOMException('Duplicate key operation', 'DataError');
    flags |= 1 << op_flag;

    // TODO(@jasnell): RFC7517 section 4.3 strong recommends validating
    // key usage combinations. Specifically, it says that unrelated key
    // ops SHOULD NOT be used together. We're not yet validating that here.
  }

  if (usagesSet !== undefined) {
    for (const use of usagesSet) {
      if (!keyOps.includes(use)) {
        throw lazyDOMException(
          'Key operations and usage mismatch',
          'DataError',
        );
      }
    }
  }
};

// WebCrypto JWK import structural validation, mirroring Node's
// `internal/crypto/webcrypto_util.validateJwk` + `validateKeyOps`:
//   - `ext`: if present and false, `extractable` must also be false
//   - `use`: if `keyUsages` is non-empty and `use` is present, must equal
//     the algorithm's expected use ('sig' or 'enc')
//   - `key_ops`: must be an array, must not contain duplicates, and every
//     requested usage must appear in it
export function validateJwkStructure(
  jwk: JWK,
  extractable: boolean,
  keyUsages: KeyUsage[],
  expectedUse: 'sig' | 'enc',
): void {
  if (jwk.ext === false && extractable) {
    throw lazyDOMException(
      'JWK "ext" is false but extractable was requested',
      'DataError',
    );
  }
  if (keyUsages.length > 0 && jwk.use !== undefined) {
    if (jwk.use !== expectedUse) {
      throw lazyDOMException('Invalid JWK "use" Parameter', 'DataError');
    }
  }
  if (jwk.key_ops !== undefined) {
    if (!Array.isArray(jwk.key_ops)) {
      throw lazyDOMException('JWK "key_ops" must be an array', 'DataError');
    }
    const seen = new Set<string>();
    for (const op of jwk.key_ops) {
      if (seen.has(op)) {
        throw lazyDOMException('Duplicate key operation', 'DataError');
      }
      seen.add(op);
    }
    for (const usage of keyUsages) {
      if (!jwk.key_ops.includes(usage)) {
        throw lazyDOMException(
          `JWK "key_ops" does not include requested usage "${usage}"`,
          'DataError',
        );
      }
    }
  }
}

export function hasAnyNotIn(set: string[], checks: string[]) {
  for (const s of set) {
    if (!checks.includes(s)) {
      return true;
    }
  }
  return false;
}
