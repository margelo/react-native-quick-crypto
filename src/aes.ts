import { promisify } from 'util';
import { NativeQuickCrypto } from './NativeQuickCrypto/NativeQuickCrypto';
import {
  lazyDOMException,
  type BufferLike,
  hasAnyNotIn,
  validateKeyOps,
  validateByteLength,
  validateMaxBufferLength,
  bufferLikeToArrayBuffer,
} from './Utils';
import {
  type ImportFormat,
  type SubtleAlgorithm,
  type KeyUsage,
  CryptoKey,
  createSecretKey,
  SecretKeyObject,
  type JWK,
  type AESAlgorithm,
  CipherOrWrapMode,
  type EncryptDecryptParams,
  type AesGcmParams,
  type AesCbcParams,
  type AesCtrParams,
  type TagLength,
  type AESLength,
  type AesKeyGenParams,
} from './keys';
import { generateKey } from './keygen';

// TODO: assign values?
export enum AESKeyVariant {
  AES_CTR_128,
  AES_CBC_128,
  AES_GCM_128,
  AES_KW_128,
  AES_CTR_192,
  AES_CBC_192,
  AES_GCM_192,
  AES_KW_192,
  AES_CTR_256,
  AES_CBC_256,
  AES_GCM_256,
  AES_KW_256,
}

const kMaxCounterLength = 128;
const kTagLengths: TagLength[] = [32, 64, 96, 104, 112, 120, 128];
const kAesKeyLengths = [128, 192, 256];

export const getAlgorithmName = (name: string, length?: number) => {
  if (length === undefined)
    throw lazyDOMException(
      `Invalid algorithm length: ${length}`,
      'SyntaxError'
    );
  switch (name) {
    case 'AES-CBC':
      return `A${length}CBC`;
    case 'AES-CTR':
      return `A${length}CTR`;
    case 'AES-GCM':
      return `A${length}GCM`;
    case 'AES-KW':
      return `A${length}KW`;
    default:
      throw lazyDOMException(`invalid algorithm name: ${name}`, 'SyntaxError');
  }
};

function validateKeyLength(length?: number) {
  if (length !== 128 && length !== 192 && length !== 256)
    throw lazyDOMException(`Invalid key length: ${length}`, 'DataError');
}

function getVariant(name: AESAlgorithm, length: AESLength): AESKeyVariant {
  switch (name) {
    case 'AES-CBC':
      switch (length) {
        case 128:
          return AESKeyVariant.AES_CBC_128;
        case 192:
          return AESKeyVariant.AES_CBC_192;
        case 256:
          return AESKeyVariant.AES_CBC_256;
      }
      // @ts-ignore
      break;
    case 'AES-CTR':
      switch (length) {
        case 128:
          return AESKeyVariant.AES_CTR_128;
        case 192:
          return AESKeyVariant.AES_CTR_192;
        case 256:
          return AESKeyVariant.AES_CTR_256;
      }
      // @ts-ignore
      break;
    case 'AES-GCM':
      switch (length) {
        case 128:
          return AESKeyVariant.AES_GCM_128;
        case 192:
          return AESKeyVariant.AES_GCM_192;
        case 256:
          return AESKeyVariant.AES_GCM_256;
      }
      // @ts-ignore
      break;
    case 'AES-KW':
      switch (length) {
        case 128:
          return AESKeyVariant.AES_KW_128;
        case 192:
          return AESKeyVariant.AES_KW_192;
        case 256:
          return AESKeyVariant.AES_KW_256;
      }
      // @ts-ignore
      break;
  }

  // @ts-ignore
  throw lazyDOMException(
    `Error getting variant ${name} at length: ${length}`,
    'DataError'
  );
}

function asyncAesCtrCipher(
  mode: CipherOrWrapMode,
  key: CryptoKey,
  data: ArrayBuffer,
  { counter, length }: AesCtrParams
): Promise<ArrayBuffer> {
  validateByteLength(counter, 'algorithm.counter', 16);
  // The length must specify an integer between 1 and 128. While
  // there is no default, this should typically be 64.
  if (length === 0 || length > kMaxCounterLength) {
    throw lazyDOMException(
      'AES-CTR algorithm.length must be between 1 and 128',
      'OperationError'
    );
  }

  return NativeQuickCrypto.webcrypto.aesCipher(
    mode,
    key.keyObject.handle,
    data,
    getVariant('AES-CTR', key.algorithm.length as AESLength),
    counter,
    length
  );
}

function asyncAesCbcCipher(
  mode: CipherOrWrapMode,
  key: CryptoKey,
  data: ArrayBuffer,
  { iv }: AesCbcParams
): Promise<ArrayBuffer> {
  validateByteLength(iv, 'algorithm.iv', 16);
  return NativeQuickCrypto.webcrypto.aesCipher(
    mode,
    key.keyObject.handle,
    data,
    getVariant('AES-CBC', key.algorithm.length as AESLength),
    bufferLikeToArrayBuffer(iv)
  );
}

// function asyncAesKwCipher(
//   mode: CipherOrWrapMode,
//   key: CryptoKey,
//   data: BufferLike
// ): Promise<ArrayBuffer> {
//   return NativeQuickCrypto.webcrypto.aesCipher(
//     mode,
//     key.keyObject.handle,
//     data,
//     getVariant('AES-KW', key.algorithm.length)
//   );
// }

function asyncAesGcmCipher(
  mode: CipherOrWrapMode,
  key: CryptoKey,
  data: ArrayBuffer,
  { iv, additionalData, tagLength = 128 }: AesGcmParams
) {
  if (!kTagLengths.includes(tagLength)) {
    throw lazyDOMException(
      `${tagLength} is not a valid AES-GCM tag length`,
      'OperationError'
    );
  }

  validateMaxBufferLength(iv, 'algorithm.iv');

  if (additionalData !== undefined) {
    validateMaxBufferLength(additionalData, 'algorithm.additionalData');
  }

  const tagByteLength = Math.floor(tagLength / 8);
  let length: number | undefined;
  let tag = new ArrayBuffer(0);
  switch (mode) {
    case CipherOrWrapMode.kWebCryptoCipherDecrypt: {
      // const slice = ArrayBuffer.isView(data)
      //   ? DataView.prototype.buffer.slice
      //   : ArrayBuffer.prototype.slice;
      tag = data.slice(-tagByteLength);

      // Refs: https://www.w3.org/TR/WebCryptoAPI/#aes-gcm-operations
      //
      // > If *plaintext* has a length less than *tagLength* bits, then `throw`
      // > an `OperationError`.
      if (tagByteLength > tag.byteLength) {
        throw lazyDOMException(
          'The provided data is too small.',
          'OperationError'
        );
      }

      data = data.slice(0, -tagByteLength);
      break;
    }
    case CipherOrWrapMode.kWebCryptoCipherEncrypt:
      length = tagByteLength;
      break;
  }

  return NativeQuickCrypto.webcrypto.aesCipher(
    mode,
    key.keyObject.handle,
    data,
    getVariant('AES-GCM', key.algorithm.length as AESLength),
    bufferLikeToArrayBuffer(iv),
    length,
    bufferLikeToArrayBuffer(tag),
    bufferLikeToArrayBuffer(additionalData || new ArrayBuffer(0))
  );
}

export const aesCipher = (
  mode: CipherOrWrapMode,
  key: CryptoKey,
  data: ArrayBuffer,
  algorithm: EncryptDecryptParams // | WrapUnwrapParams
): Promise<ArrayBuffer> => {
  switch (algorithm.name) {
    case 'AES-CTR':
      return asyncAesCtrCipher(mode, key, data, algorithm);
    case 'AES-CBC':
      return asyncAesCbcCipher(mode, key, data, algorithm);
    case 'AES-GCM':
      return asyncAesGcmCipher(mode, key, data, algorithm);
    // case 'AES-KW':
    //   return asyncAesKwCipher(mode, key, data);
  }
  throw new Error(`aesCipher: Unknown algorithm ${algorithm.name}`);
};

const generateKeyAsync = promisify(generateKey);

export const aesGenerateKey = async (
  algorithm: AesKeyGenParams,
  extractable: boolean,
  keyUsages: KeyUsage[]
): Promise<CryptoKey> => {
  const { name, length } = algorithm;
  if (!name) {
    throw lazyDOMException('Algorithm name is undefined', 'SyntaxError');
  }
  if (!kAesKeyLengths.includes(length)) {
    throw lazyDOMException(
      'AES key length must be 128, 192, or 256 bits',
      'OperationError'
    );
  }

  const checkUsages = ['wrapKey', 'unwrapKey'];
  if (name !== 'AES-KW') {
    checkUsages.push('encrypt', 'decrypt');
  }
  // const usagesSet = new SafeSet(keyUsages);
  if (hasAnyNotIn(keyUsages, checkUsages)) {
    throw lazyDOMException(
      `Unsupported key usage for an AES key: ${keyUsages}`,
      'SyntaxError'
    );
  }

  const key = await generateKeyAsync('aes', { length }).catch((err: Error) => {
    throw lazyDOMException(
      'The operation failed for an operation-specific reason' +
        `[${err.message}]`,
      { name: 'OperationError', cause: err }
    );
  });

  return new CryptoKey(
    key as SecretKeyObject,
    { name, length },
    Array.from(keyUsages),
    extractable
  );
};

export const aesImportKey = async (
  algorithm: SubtleAlgorithm,
  format: ImportFormat,
  keyData: BufferLike | JWK,
  extractable: boolean,
  keyUsages: KeyUsage[]
): Promise<CryptoKey> => {
  const { name } = algorithm;
  const checkUsages = ['wrapKey', 'unwrapKey'];
  if (name !== 'AES-KW') {
    checkUsages.push('encrypt', 'decrypt');
  }

  // const usagesSet = new SafeSet(keyUsages);
  if (hasAnyNotIn(keyUsages, checkUsages)) {
    throw lazyDOMException(
      'Unsupported key usage for an AES key',
      'SyntaxError'
    );
  }

  let keyObject: SecretKeyObject;
  let length: number | undefined;

  switch (format) {
    case 'raw': {
      const data = keyData as BufferLike;
      validateKeyLength(data.byteLength * 8);
      keyObject = createSecretKey(keyData);
      break;
    }
    case 'jwk': {
      const data = keyData as JWK;

      if (!data.kty) throw lazyDOMException('Invalid keyData', 'DataError');

      if (data.kty !== 'oct')
        throw lazyDOMException('Invalid JWK "kty" Parameter', 'DataError');

      if (
        keyUsages.length > 0 &&
        data.use !== undefined &&
        data.use !== 'enc'
      ) {
        throw lazyDOMException('Invalid JWK "use" Parameter', 'DataError');
      }

      validateKeyOps(data.key_ops, keyUsages);

      if (
        data.ext !== undefined &&
        data.ext === false &&
        extractable === true
      ) {
        throw lazyDOMException(
          'JWK "ext" Parameter and extractable mismatch',
          'DataError'
        );
      }

      const handle = NativeQuickCrypto.webcrypto.createKeyObjectHandle();
      handle.initJwk(data);

      ({ length } = handle.keyDetail());
      validateKeyLength(length);

      if (data.alg !== undefined) {
        if (data.alg !== getAlgorithmName(algorithm.name, length))
          throw lazyDOMException(
            'JWK "alg" does not match the requested algorithm',
            'DataError'
          );
      }

      keyObject = new SecretKeyObject(handle);
      break;
    }
    default:
      throw lazyDOMException(
        `Unable to import AES key with format ${format}`,
        'NotSupportedError'
      );
  }

  if (length === undefined) {
    ({ length } = keyObject.handle.keyDetail());
    validateKeyLength(length);
  }

  return new CryptoKey(keyObject, { name, length }, keyUsages, extractable);
};
