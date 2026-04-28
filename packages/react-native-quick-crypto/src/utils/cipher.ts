import type { Encoding } from './types';

// Mimics node behavior for default global encoding
let defaultEncoding: Encoding = 'buffer';

export function setDefaultEncoding(encoding: Encoding) {
  defaultEncoding = encoding;
}

export function getDefaultEncoding(): Encoding {
  return defaultEncoding;
}

export function normalizeEncoding(enc: string) {
  if (!enc) return 'utf8';
  let retried;
  while (true) {
    switch (enc) {
      case 'utf8':
      case 'utf-8':
        return 'utf8';
      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return 'utf16le';
      case 'latin1':
      case 'binary':
        return 'latin1';
      case 'base64':
      case 'ascii':
      case 'hex':
        return enc;
      default:
        if (retried) return; // undefined
        enc = ('' + enc).toLowerCase();
        retried = true;
    }
  }
}

export function validateEncoding(data: string, encoding: string) {
  const normalizedEncoding = normalizeEncoding(encoding);
  const length = data.length;

  if (normalizedEncoding === 'hex' && length % 2 !== 0) {
    throw new Error(`Encoding ${encoding} not valid for data length ${length}`);
  }
}

/**
 * Reads an unsigned-integer option from an options-like object.
 *
 * Returns `undefined` if the option is missing, `null`, or `undefined`.
 * Throws `RangeError` if the value is present but not a non-negative
 * 32-bit integer (NaN, Infinity, fractional, negative, or > 2^32 - 1).
 *
 * Replaces the previous `Record<string, any>` + sentinel-`-1` signature,
 * which defeated the type checker (audit Phase 1.4). Callers that used
 * `getUIntOption(opts ?? {}, key) !== -1 ? getUIntOption(...) : default`
 * collapse to `getUIntOption(opts, key) ?? default`.
 */
export function getUIntOption(
  options: Readonly<Record<string, unknown>> | undefined,
  key: string,
): number | undefined {
  if (options == null) return undefined;
  const value = options[key];
  if (value == null) return undefined;
  if (
    typeof value !== 'number' ||
    !Number.isFinite(value) ||
    !Number.isInteger(value) ||
    value < 0 ||
    value > 0xffff_ffff
  ) {
    throw new RangeError(
      `options.${key} must be a non-negative 32-bit integer, got ${String(value)}`,
    );
  }
  return value;
}
