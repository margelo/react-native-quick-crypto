import { Buffer as SBuffer } from 'safe-buffer';
import type { BinaryLike, BufferLike, KeyUsage } from './types';
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

export const getUsagesUnion = (usageSet: KeyUsage[], ...usages: KeyUsage[]) => {
  const newset: KeyUsage[] = [];
  for (let n = 0; n < usages.length; n++) {
    if (!usages[n] || usages[n] === undefined) continue;
    if (usageSet.includes(usages[n] as KeyUsage))
      newset.push(usages[n] as KeyUsage);
  }
  return newset;
};

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

export function hasAnyNotIn(set: string[], checks: string[]) {
  for (const s of set) {
    if (!checks.includes(s)) {
      return true;
    }
  }
  return false;
}
