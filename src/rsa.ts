import { KeyVariantLookup } from './NativeQuickCrypto/Cipher';
import { generateKeyPairPromise } from './Cipher';
import { NativeQuickCrypto } from './NativeQuickCrypto/NativeQuickCrypto';
import type { KeyObjectHandle } from './NativeQuickCrypto/webcrypto';
import {
  lazyDOMException,
  type BufferLike,
  validateKeyOps,
  normalizeHashName,
  HashContext,
  hasAnyNotIn,
  getUsagesUnion,
  bigIntArrayToUnsignedInt,
  validateMaxBufferLength,
  bufferLikeToArrayBuffer,
} from './Utils';
import {
  CryptoKey,
  PrivateKeyObject,
  type HashAlgorithm,
  type ImportFormat,
  type JWK,
  type KeyUsage,
  type SubtleAlgorithm,
  PublicKeyObject,
  type AnyAlgorithm,
  KeyType,
  createPublicKey,
  type CryptoKeyPair,
  KWebCryptoKeyFormat,
  CipherOrWrapMode,
  type RsaOaepParams,
  type DigestAlgorithm,
} from './keys';

// TODO: keep in in sync with C++ side (cpp/Cipher/MGLRsa.h)
export enum RSAKeyVariant {
  RSA_SSA_PKCS1_v1_5,
  RSA_PSS,
  RSA_OAEP,
}

function verifyAcceptableRsaKeyUse(
  name: AnyAlgorithm,
  isPublic: boolean,
  usages: KeyUsage[]
): void {
  let checkSet;
  switch (name) {
    case 'RSA-OAEP':
      checkSet = isPublic ? ['encrypt', 'wrapKey'] : ['decrypt', 'unwrapKey'];
      break;
    case 'RSA-PSS':
    // Fall through
    case 'RSASSA-PKCS1-v1_5':
      checkSet = isPublic ? ['verify'] : ['sign'];
      break;
    default:
      throw lazyDOMException(
        'The algorithm is not supported',
        'NotSupportedError'
      );
  }
  if (hasAnyNotIn(usages, checkSet)) {
    throw lazyDOMException(
      `Unsupported key usage for an ${name} key`,
      'SyntaxError'
    );
  }
}

const rsaOaepCipher = (
  mode: CipherOrWrapMode,
  key: CryptoKey,
  data: ArrayBuffer,
  { label }: RsaOaepParams
): Promise<ArrayBuffer> => {
  const type =
    mode === CipherOrWrapMode.kWebCryptoCipherEncrypt ? 'public' : 'private';
  if (key.type !== type) {
    throw lazyDOMException(
      'The requested operation is not valid for the provided key',
      'InvalidAccessError'
    );
  }
  if (label !== undefined) {
    validateMaxBufferLength(label, 'algorithm.label');
  }

  return NativeQuickCrypto.webcrypto.rsaCipher(
    mode,
    key.keyObject.handle,
    data,
    RSAKeyVariant.RSA_OAEP,
    normalizeHashName(key.algorithm.hash) as DigestAlgorithm,
    label !== undefined ? bufferLikeToArrayBuffer(label) : undefined
  );
};

export const rsaCipher = rsaOaepCipher;

export const rsaKeyGenerate = async (
  algorithm: SubtleAlgorithm,
  extractable: boolean,
  keyUsages: KeyUsage[]
): Promise<CryptoKeyPair> => {
  const { name, modulusLength, publicExponent, hash: rawHash } = algorithm;
  const hash: HashAlgorithm = normalizeHashName(rawHash);

  // const usageSet = new SafeSet(keyUsages);
  const publicExponentConverted = bigIntArrayToUnsignedInt(publicExponent as Uint8Array);
  if (publicExponentConverted === undefined) {
    throw lazyDOMException(
      'The publicExponent must be equivalent to an unsigned 32-bit value',
      'OperationError'
    );
  }

  switch (name) {
    case 'RSA-OAEP':
      if (
        hasAnyNotIn(keyUsages, ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'])
      ) {
        throw lazyDOMException(
          'Unsupported key usage for a RSA key',
          'SyntaxError'
        );
      }
      break;
    default:
      if (hasAnyNotIn(keyUsages, ['sign', 'verify'])) {
        throw lazyDOMException(
          'Unsupported key usage for a RSA key',
          'SyntaxError'
        );
      }
  }

  const [err, keypair] = await generateKeyPairPromise('rsa', {
    modulusLength,
    publicExponent: publicExponentConverted,
  });
  if (err) {
    throw lazyDOMException(
      'The operation failed for an operation-specific reason',
      { name: 'OperationError', cause: err }
    );
  }

  const keyAlgorithm = {
    name,
    modulusLength,
    publicExponent: publicExponentConverted,
    hash,
  };

  let publicUsages: KeyUsage[] = [];
  let privateUsages: KeyUsage[] = [];
  switch (name) {
    case 'RSA-OAEP': {
      publicUsages = getUsagesUnion(keyUsages, 'encrypt', 'wrapKey');
      privateUsages = getUsagesUnion(keyUsages, 'decrypt', 'unwrapKey');
      break;
    }
    default: {
      publicUsages = getUsagesUnion(keyUsages, 'verify');
      privateUsages = getUsagesUnion(keyUsages, 'sign');
      break;
    }
  }

  const pub = new PublicKeyObject(keypair?.publicKey as KeyObjectHandle);
  const publicKey = new CryptoKey(pub, keyAlgorithm, publicUsages, true);

  const priv = new PrivateKeyObject(keypair?.privateKey as KeyObjectHandle);
  const privateKey = new CryptoKey(
    priv,
    keyAlgorithm,
    privateUsages,
    extractable
  );

  return { publicKey, privateKey };
};

export const rsaExportKey = (
  key: CryptoKey,
  format: KWebCryptoKeyFormat
): ArrayBuffer => {
  const variant = KeyVariantLookup[key.algorithm.name];
  if (variant === undefined) {
    throw lazyDOMException(
      `Unrecognized algorithm name '${key.algorithm.name}'`,
      'NotSupportedError'
    );
  }
  return NativeQuickCrypto.webcrypto.rsaExportKey(
    format,
    key.keyObject.handle,
    variant
  );
};

export const rsaImportKey = (
  format: ImportFormat,
  keyData: BufferLike | JWK,
  algorithm: SubtleAlgorithm,
  extractable: boolean,
  keyUsages: KeyUsage[]
): CryptoKey => {
  // const usagesSet = new SafeSet(keyUsages);
  let keyObject: PublicKeyObject | PrivateKeyObject;
  switch (format) {
    case 'spki': {
      verifyAcceptableRsaKeyUse(algorithm.name, true, keyUsages);
      try {
        keyObject = createPublicKey({
          key: keyData,
          format: 'der',
          type: 'spki',
        });
      } catch (err) {
        throw lazyDOMException('Invalid keyData', {
          name: 'DataError',
          cause: err,
        });
      }
      break;
    }
    // case 'pkcs8': {
    //   verifyAcceptableRsaKeyUse(algorithm.name, false, keyUsages);
    //   try {
    //     keyObject = createPrivateKey({
    //       key: keyData,
    //       format: 'der',
    //       type: 'pkcs8',
    //     });
    //   } catch (err) {
    //     throw lazyDOMException('Invalid keyData', {
    //       name: 'DataError',
    //       cause: err,
    //     });
    //   }
    //   break;
    // }
    case 'jwk': {
      const data = keyData as JWK;
      if (!data.kty) {
        throw lazyDOMException('Invalid keyData', 'DataError');
      }
      if (data.kty !== 'RSA')
        throw lazyDOMException('Invalid JWK "kty" Parameter', 'DataError');

      verifyAcceptableRsaKeyUse(
        algorithm.name,
        data.d === undefined,
        keyUsages
      );

      if (keyUsages.length > 0 && data.use !== undefined) {
        const checkUse = algorithm.name === 'RSA-OAEP' ? 'enc' : 'sig';
        if (data.use !== checkUse)
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

      if (data.alg !== undefined) {
        const hash = normalizeHashName(
          data.alg as HashAlgorithm,
          HashContext.WebCrypto
        );
        if (hash !== algorithm.hash)
          throw lazyDOMException(
            'JWK "alg" does not match the requested algorithm',
            'DataError'
          );
      }

      const handle = NativeQuickCrypto.webcrypto.createKeyObjectHandle();
      const type = handle.initJwk(data);
      if (type === undefined)
        throw lazyDOMException('Invalid JWK', 'DataError');

      keyObject =
        type === KeyType.Private
          ? new PrivateKeyObject(handle)
          : new PublicKeyObject(handle);

      break;
    }
    default:
      throw lazyDOMException(
        `Unable to import RSA key with format ${format}`,
        'NotSupportedError'
      );
  }

  if (keyObject.asymmetricKeyType !== 'rsa') {
    throw lazyDOMException('Invalid key type', 'DataError');
  }

  const { modulusLength, publicExponent } = keyObject.handle.keyDetail();

  if (publicExponent === undefined) {
    throw lazyDOMException('publicExponent is undefined', 'DataError');
  }

  return new CryptoKey(
    keyObject,
    {
      name: algorithm.name,
      modulusLength,
      publicExponent: new Uint8Array(publicExponent),
      hash: algorithm.hash,
    },
    keyUsages,
    extractable
  );
};

// function rsaSignVerify(key, data, { saltLength }, signature) {
//   let padding;
//   if (key.algorithm.name === 'RSA-PSS') {
//     padding = RSA_PKCS1_PSS_PADDING;
//     // TODO(@jasnell): Validate maximum size of saltLength
//     // based on the key size:
//     //   Math.ceil((keySizeInBits - 1)/8) - digestSizeInBytes - 2
//     validateInt32(saltLength, 'algorithm.saltLength', -2);
//   }

//   const mode = signature === undefined ? kSignJobModeSign : kSignJobModeVerify;
//   const type = mode === kSignJobModeSign ? 'private' : 'public';

//   if (key.type !== type)
//     throw lazyDOMException(`Key must be a ${type} key`, 'InvalidAccessError');

//   return jobPromise(() => new SignJob(
//     kCryptoJobAsync,
//     signature === undefined ? kSignJobModeSign : kSignJobModeVerify,
//     key[kKeyObject][kHandle],
//     undefined,
//     undefined,
//     undefined,
//     data,
//     normalizeHashName(key.algorithm.hash.name),
//     saltLength,
//     padding,
//     undefined,
//     signature));
// }

// module.exports = {
//   rsaCipher: rsaOaepCipher,
//   rsaExportKey,
//   rsaImportKey,
//   rsaKeyGenerate,
//   rsaSignVerify,
// };
