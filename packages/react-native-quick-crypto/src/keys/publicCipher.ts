import { NitroModules } from 'react-native-nitro-modules';
import type { RsaCipher } from '../specs/rsaCipher.nitro';
import type { BinaryLike } from '../utils';
import {
  binaryLikeToArrayBuffer as toAB,
  isStringOrBuffer,
  KFormatType,
  KeyEncoding,
} from '../utils';
import { isCryptoKey } from './utils';
import { KeyObject, CryptoKey } from './classes';

interface PublicCipherOptions {
  key: BinaryLike | KeyObject | CryptoKey;
  padding?: number;
  oaepHash?: string;
  oaepLabel?: BinaryLike;
}

type PublicCipherInput =
  | BinaryLike
  | KeyObject
  | CryptoKey
  | PublicCipherOptions;

function preparePublicCipherKey(
  key: PublicCipherInput,
  isEncrypt: boolean,
): {
  keyHandle: KeyObject;
  padding?: number;
  oaepHash?: string;
  oaepLabel?: ArrayBuffer;
} {
  let keyObj: KeyObject;
  let padding: number | undefined;
  let oaepHash: string | undefined;
  let oaepLabel: ArrayBuffer | undefined;

  if (key instanceof KeyObject) {
    if (isEncrypt && key.type !== 'public') {
      throw new Error('publicEncrypt requires a public key');
    }
    if (!isEncrypt && key.type !== 'private') {
      throw new Error('publicDecrypt requires a private key');
    }
    keyObj = key;
  } else if (isCryptoKey(key)) {
    const cryptoKey = key as CryptoKey;
    keyObj = cryptoKey.keyObject;
  } else if (isStringOrBuffer(key)) {
    const data = toAB(key);
    // Detect if it's PEM format (contains PEM headers) or DER binary
    const isPem = typeof key === 'string' && key.includes('-----BEGIN');
    keyObj = KeyObject.createKeyObject(
      isEncrypt ? 'public' : 'private',
      data,
      isPem ? KFormatType.PEM : KFormatType.DER,
      isEncrypt ? KeyEncoding.SPKI : KeyEncoding.PKCS8,
    );
  } else if (typeof key === 'object' && 'key' in key) {
    const options = key as PublicCipherOptions;
    const result = preparePublicCipherKey(options.key, isEncrypt);
    keyObj = result.keyHandle;
    padding = options.padding;
    oaepHash = options.oaepHash;
    if (options.oaepLabel) {
      oaepLabel = toAB(options.oaepLabel);
    }
  } else {
    throw new Error('Invalid key input');
  }

  return { keyHandle: keyObj, padding, oaepHash, oaepLabel };
}

export function publicEncrypt(
  key: PublicCipherInput,
  buffer: BinaryLike,
): Buffer {
  const { keyHandle, oaepHash, oaepLabel } = preparePublicCipherKey(key, true);

  const rsaCipher: RsaCipher = NitroModules.createHybridObject('RsaCipher');
  const data = toAB(buffer);
  const hashAlgorithm = oaepHash || 'SHA-256';

  try {
    const encrypted = rsaCipher.encrypt(
      keyHandle.handle,
      data,
      hashAlgorithm,
      oaepLabel,
    );
    return Buffer.from(encrypted);
  } catch (error) {
    throw new Error(`publicEncrypt failed: ${(error as Error).message}`);
  }
}

export function publicDecrypt(
  key: PublicCipherInput,
  buffer: BinaryLike,
): Buffer {
  const { keyHandle, oaepHash, oaepLabel } = preparePublicCipherKey(key, false);

  const rsaCipher: RsaCipher = NitroModules.createHybridObject('RsaCipher');
  const data = toAB(buffer);
  const hashAlgorithm = oaepHash || 'SHA-256';

  try {
    const decrypted = rsaCipher.decrypt(
      keyHandle.handle,
      data,
      hashAlgorithm,
      oaepLabel,
    );
    return Buffer.from(decrypted);
  } catch (error) {
    throw new Error(`publicDecrypt failed: ${(error as Error).message}`);
  }
}
