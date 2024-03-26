// 'use strict';

import { NativeQuickCrypto } from './NativeQuickCrypto/NativeQuickCrypto';
import {
  lazyDOMException,
  type BufferLike,
  validateKeyOps,
  normalizeHashName,
  HashContext,
  hasAnyNotIn,
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
} from './keys';

// const {
//   SafeSet,
//   Uint8Array,
// } = primordials;

// const {
//   KeyObjectHandle,
//   RSACipherJob,
//   RSAKeyExportJob,
//   SignJob,
//   kCryptoJobAsync,
//   kSignJobModeSign,
//   kSignJobModeVerify,
//   kKeyVariantRSA_SSA_PKCS1_v1_5,
//   kKeyVariantRSA_PSS,
//   kKeyVariantRSA_OAEP,
//   kKeyTypePrivate,
//   kWebCryptoCipherEncrypt,
//   RSA_PKCS1_PSS_PADDING,
// } = internalBinding('crypto');

// const {
//   validateInt32,
// } = require('internal/validators');

// const {
//   bigIntArrayToUnsignedInt,
//   getUsagesUnion,
//   hasAnyNotIn,
//   jobPromise,
//   normalizeHashName,
//   validateKeyOps,
//   validateMaxBufferLength,
//   kHandle,
//   kKeyObject,
// } = require('internal/crypto/util');

// const {
//   lazyDOMException,
//   promisify,
// } = require('internal/util');

// const {
//   InternalCryptoKey,
//   PrivateKeyObject,
//   PublicKeyObject,
//   createPublicKey,
//   createPrivateKey,
// } = require('internal/crypto/keys');

// const {
//   generateKeyPair: _generateKeyPair,
// } = require('internal/crypto/keygen');

// const kRsaVariants = {
//   'RSASSA-PKCS1-v1_5': kKeyVariantRSA_SSA_PKCS1_v1_5,
//   'RSA-PSS': kKeyVariantRSA_PSS,
//   'RSA-OAEP': kKeyVariantRSA_OAEP,
// };
// const generateKeyPair = promisify(_generateKeyPair);

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

// function rsaOaepCipher(mode, key, data, { label }) {
//   const type = mode === kWebCryptoCipherEncrypt ? 'public' : 'private';
//   if (key.type !== type) {
//     throw lazyDOMException(
//       'The requested operation is not valid for the provided key',
//       'InvalidAccessError');
//   }
//   if (label !== undefined) {
//     validateMaxBufferLength(label, 'algorithm.label');
//   }

//   return jobPromise(() => new RSACipherJob(
//     kCryptoJobAsync,
//     mode,
//     key[kKeyObject][kHandle],
//     data,
//     kKeyVariantRSA_OAEP,
//     normalizeHashName(key.algorithm.hash.name),
//     label));
// }

// async function rsaKeyGenerate(
//   algorithm,
//   extractable,
//   keyUsages) {

//   const {
//     name,
//     modulusLength,
//     publicExponent,
//     hash,
//   } = algorithm;

//   const usageSet = new SafeSet(keyUsages);

//   const publicExponentConverted = bigIntArrayToUnsignedInt(publicExponent);
//   if (publicExponentConverted === undefined) {
//     throw lazyDOMException(
//       'The publicExponent must be equivalent to an unsigned 32-bit value',
//       'OperationError');
//   }

//   switch (name) {
//     case 'RSA-OAEP':
//       if (hasAnyNotIn(usageSet,
//                       ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'])) {
//         throw lazyDOMException(
//           'Unsupported key usage for a RSA key',
//           'SyntaxError');
//       }
//       break;
//     default:
//       if (hasAnyNotIn(usageSet, ['sign', 'verify'])) {
//         throw lazyDOMException(
//           'Unsupported key usage for a RSA key',
//           'SyntaxError');
//       }
//   }

//   const keypair = await generateKeyPair('rsa', {
//     modulusLength,
//     publicExponent: publicExponentConverted,
//   }).catch((err) => {
//     throw lazyDOMException(
//       'The operation failed for an operation-specific reason',
//       { name: 'OperationError', cause: err });
//   });

//   const keyAlgorithm = {
//     name,
//     modulusLength,
//     publicExponent,
//     hash: { name: hash.name },
//   };

//   let publicUsages;
//   let privateUsages;
//   switch (name) {
//     case 'RSA-OAEP': {
//       publicUsages = getUsagesUnion(usageSet, 'encrypt', 'wrapKey');
//       privateUsages = getUsagesUnion(usageSet, 'decrypt', 'unwrapKey');
//       break;
//     }
//     default: {
//       publicUsages = getUsagesUnion(usageSet, 'verify');
//       privateUsages = getUsagesUnion(usageSet, 'sign');
//       break;
//     }
//   }

//   const publicKey =
//     new InternalCryptoKey(
//       keypair.publicKey,
//       keyAlgorithm,
//       publicUsages,
//       true);

//   const privateKey =
//     new InternalCryptoKey(
//       keypair.privateKey,
//       keyAlgorithm,
//       privateUsages,
//       extractable);

//   return { __proto__: null, publicKey, privateKey };
// }

// function rsaExportKey(key, format) {
//   return jobPromise(() => new RSAKeyExportJob(
//     kCryptoJobAsync,
//     format,
//     key[kKeyObject][kHandle],
//     kRsaVariants[key.algorithm.name]));
// }

export const rsaImportKey = (
  format: ImportFormat,
  keyData: BufferLike | JWK,
  algorithm: SubtleAlgorithm,
  extractable: boolean,
  keyUsages: KeyUsage[]
): CryptoKey => {
  // const usagesSet = new SafeSet(keyUsages);
  let keyObject;
  switch (format) {
    // case 'spki': {
    //   verifyAcceptableRsaKeyUse(algorithm.name, true, keyUsages);
    //   try {
    //     keyObject = createPublicKey({
    //       key: keyData,
    //       format: 'der',
    //       type: 'spki',
    //     });
    //   } catch (err) {
    //     throw lazyDOMException('Invalid keyData', {
    //       name: 'DataError',
    //       cause: err,
    //     });
    //   }
    //   break;
    // }
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
