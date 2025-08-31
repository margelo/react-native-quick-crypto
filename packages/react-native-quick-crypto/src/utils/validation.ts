import { Buffer as SBuffer } from 'safe-buffer';
import type { BinaryLike, BufferLike } from './types';
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
