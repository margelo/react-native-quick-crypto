import { StringDecoder } from "string_decoder";
import type { Encoding } from "./types";

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

export function getDecoder(decoder?: StringDecoder, encoding?: BufferEncoding) {
  return decoder ?? new StringDecoder(encoding);
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function getUIntOption(options: Record<string, any>, key: string) {
  let value;
  if (options && (value = options[key]) != null) {
    // >>> Turns any type into a positive integer (also sets the sign bit to 0)
    if (value >>> 0 !== value) throw new Error(`options.${key}: ${value}`);
    return value;
  }
  return -1;
}
