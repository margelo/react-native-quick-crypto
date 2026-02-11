import { Buffer } from '@craftzdog/react-native-buffer';
import { NitroModules } from 'react-native-nitro-modules';
import type {
  SignHandle as SignHandleSpec,
  VerifyHandle as VerifyHandleSpec,
} from '../specs/sign.nitro';
import { KeyObject, CryptoKey } from './classes';
import { isCryptoKey } from './utils';
import type { BinaryLike } from '../utils';
import {
  binaryLikeToArrayBuffer as toAB,
  isStringOrBuffer,
  KFormatType,
  KeyEncoding,
} from '../utils';

type KeyInput = BinaryLike | KeyObject | CryptoKey | KeyInputObject;

interface KeyInputObject {
  key: BinaryLike | KeyObject | CryptoKey;
  format?: 'pem' | 'der';
  type?: 'pkcs1' | 'pkcs8' | 'spki' | 'sec1';
  passphrase?: BinaryLike;
  padding?: number;
  saltLength?: number;
  dsaEncoding?: 'der' | 'ieee-p1363';
}

interface SignOptions {
  padding?: number;
  saltLength?: number;
  dsaEncoding?: 'der' | 'ieee-p1363';
}

interface PreparedKey {
  keyObject: KeyObject;
  options?: SignOptions;
}

function prepareKey(key: KeyInput, isPublic: boolean): PreparedKey {
  // Already a KeyObject
  if (key instanceof KeyObject) {
    if (isPublic) {
      if (key.type === 'secret') {
        throw new Error('Cannot use secret key for signature verification');
      }
    } else {
      if (key.type !== 'private') {
        throw new Error('Key must be a private key for signing');
      }
    }
    return { keyObject: key };
  }

  // CryptoKey - extract KeyObject
  if (isCryptoKey(key)) {
    const cryptoKey = key as CryptoKey;
    return prepareKey(cryptoKey.keyObject, isPublic);
  }

  // Raw string or buffer - create KeyObject
  if (isStringOrBuffer(key)) {
    const isPem = typeof key === 'string' && key.includes('-----BEGIN');
    const format = isPem ? KFormatType.PEM : undefined;
    const type = isPublic ? 'public' : 'private';
    const keyData = toAB(key);
    const keyObject = KeyObject.createKeyObject(type, keyData, format);
    return { keyObject };
  }

  // KeyInputObject with options
  if (typeof key === 'object' && 'key' in key) {
    const keyObj = key as KeyInputObject;
    const {
      key: data,
      format,
      type,
      padding,
      saltLength,
      dsaEncoding,
    } = keyObj;

    // Nested KeyObject
    if (data instanceof KeyObject) {
      return {
        keyObject: data,
        options: { padding, saltLength, dsaEncoding },
      };
    }

    // Nested CryptoKey
    if (isCryptoKey(data)) {
      return {
        keyObject: (data as CryptoKey).keyObject,
        options: { padding, saltLength, dsaEncoding },
      };
    }

    if (!isStringOrBuffer(data)) {
      throw new Error('Invalid key data type');
    }

    // Determine format
    const isPem =
      format === 'pem' ||
      (typeof data === 'string' && data.includes('-----BEGIN'));
    const kFormat = isPem
      ? KFormatType.PEM
      : format === 'der'
        ? KFormatType.DER
        : undefined;

    // Determine encoding type
    let kType: KeyEncoding | undefined;
    if (type === 'pkcs8') kType = KeyEncoding.PKCS8;
    else if (type === 'pkcs1') kType = KeyEncoding.PKCS1;
    else if (type === 'sec1') kType = KeyEncoding.SEC1;
    else if (type === 'spki') kType = KeyEncoding.SPKI;

    const keyType = isPublic ? 'public' : 'private';
    // Always convert to ArrayBuffer to avoid Nitro bridge string truncation bug
    const originalLength =
      typeof data === 'string' ? data.length : data.byteLength;
    const keyData = toAB(data);
    console.log(
      `[prepareKey KeyInputObject] ${keyType} key, original length: ${originalLength}, ArrayBuffer size: ${keyData.byteLength}`,
    );
    const keyObject = KeyObject.createKeyObject(
      keyType,
      keyData,
      kFormat,
      kType,
    );

    return {
      keyObject,
      options: { padding, saltLength, dsaEncoding },
    };
  }

  throw new Error('Invalid key input');
}

function dsaEncodingToNumber(
  dsaEncoding?: 'der' | 'ieee-p1363',
): number | undefined {
  if (dsaEncoding === 'der') return 0;
  if (dsaEncoding === 'ieee-p1363') return 1;
  return undefined;
}

export class Sign {
  private handle: SignHandleSpec;

  constructor(algorithm: string) {
    this.handle = NitroModules.createHybridObject<SignHandleSpec>('SignHandle');
    this.handle.init(algorithm);
  }

  update(data: BinaryLike): this {
    const dataBuffer = toAB(data);
    this.handle.update(dataBuffer);
    return this;
  }

  sign(privateKey: KeyInput, outputEncoding?: BufferEncoding): Buffer;
  sign(privateKey: KeyInput, outputEncoding?: BufferEncoding): Buffer | string {
    if (privateKey === null || privateKey === undefined) {
      throw new Error('Private key is required');
    }

    const { keyObject, options } = prepareKey(privateKey, false);

    const signature = this.handle.sign(
      keyObject.handle,
      options?.padding,
      options?.saltLength,
      dsaEncodingToNumber(options?.dsaEncoding),
    );

    const buf = Buffer.from(signature);
    if (outputEncoding) {
      return buf.toString(outputEncoding);
    }
    return buf;
  }
}

export class Verify {
  private handle: VerifyHandleSpec;

  constructor(algorithm: string) {
    this.handle =
      NitroModules.createHybridObject<VerifyHandleSpec>('VerifyHandle');
    this.handle.init(algorithm);
  }

  update(data: BinaryLike): this {
    const dataBuffer = toAB(data);
    this.handle.update(dataBuffer);
    return this;
  }

  verify(
    publicKey: KeyInput,
    signature: BinaryLike,
    signatureEncoding?: BufferEncoding,
  ): boolean {
    if (publicKey === null || publicKey === undefined) {
      throw new Error('Public key is required');
    }

    const { keyObject, options } = prepareKey(publicKey, true);

    // Convert signature to ArrayBuffer
    let sigBuffer: ArrayBuffer;
    if (signatureEncoding && typeof signature === 'string') {
      sigBuffer = toAB(Buffer.from(signature, signatureEncoding));
    } else {
      sigBuffer = toAB(signature);
    }

    return this.handle.verify(
      keyObject.handle,
      sigBuffer,
      options?.padding,
      options?.saltLength,
      dsaEncodingToNumber(options?.dsaEncoding),
    );
  }
}

export function createSign(algorithm: string): Sign {
  return new Sign(algorithm);
}

export function createVerify(algorithm: string): Verify {
  return new Verify(algorithm);
}

type SignCallback = (err: Error | null, signature?: Buffer) => void;
type VerifyCallback = (err: Error | null, result?: boolean) => void;

export function sign(
  algorithm: string | null | undefined,
  data: BinaryLike,
  key: KeyInput,
): Buffer;
export function sign(
  algorithm: string | null | undefined,
  data: BinaryLike,
  key: KeyInput,
  callback: SignCallback,
): void;
export function sign(
  algorithm: string | null | undefined,
  data: BinaryLike,
  key: KeyInput,
  callback?: SignCallback,
): Buffer | void {
  const doSign = (): Buffer => {
    if (key === null || key === undefined) {
      throw new Error('Private key is required');
    }
    const signer = new Sign(algorithm ?? '');
    signer.update(data);
    return signer.sign(key);
  };

  if (callback) {
    try {
      const signature = doSign();
      process.nextTick(callback, null, signature);
    } catch (err) {
      process.nextTick(callback, err as Error);
    }
    return;
  }

  return doSign();
}

export function verify(
  algorithm: string | null | undefined,
  data: BinaryLike,
  key: KeyInput,
  signature: BinaryLike,
): boolean;
export function verify(
  algorithm: string | null | undefined,
  data: BinaryLike,
  key: KeyInput,
  signature: BinaryLike,
  callback: VerifyCallback,
): void;
export function verify(
  algorithm: string | null | undefined,
  data: BinaryLike,
  key: KeyInput,
  signature: BinaryLike,
  callback?: VerifyCallback,
): boolean | void {
  const doVerify = (): boolean => {
    if (key === null || key === undefined) {
      throw new Error('Key is required');
    }
    const verifier = new Verify(algorithm ?? '');
    verifier.update(data);
    return verifier.verify(key, signature);
  };

  if (callback) {
    try {
      const result = doVerify();
      process.nextTick(callback, null, result);
    } catch (err) {
      process.nextTick(callback, err as Error);
    }
    return;
  }

  return doVerify();
}
