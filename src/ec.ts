import { NativeQuickCrypto } from './NativeQuickCrypto/NativeQuickCrypto';
import { bufferLikeToArrayBuffer, type BufferLike } from './Utils';
import {
  type ImportFormat,
  type SubtleAlgorithm,
  type KeyUsage,
  kNamedCurveAliases,
  type NamedCurve,
  PublicKeyObject,
  KWebCryptoKeyFormat,
  CryptoKey,
} from './keys';

// const {
//   ArrayPrototypeIncludes,
//   ObjectKeys,
//   SafeSet,
// } = primordials;

// const {
//   ECKeyExportJob,
//   KeyObjectHandle,
//   SignJob,
//   kCryptoJobAsync,
//   kKeyTypePrivate,
//   kSignJobModeSign,
//   kSignJobModeVerify,
//   kSigEncP1363,
// } = internalBinding('crypto');

// const {
//   getUsagesUnion,
//   hasAnyNotIn,
//   jobPromise,
//   normalizeHashName,
//   validateKeyOps,
//   kHandle,
//   kKeyObject,
//   kNamedCurveAliases,
// } = require('internal/crypto/util');

// const {
//   lazyDOMException,
//   promisify,
// } = require('internal/util');

// const {
//   generateKeyPair: _generateKeyPair,
// } = require('internal/crypto/keygen');

// const {
//   InternalCryptoKey,
//   PrivateKeyObject,
//   PublicKeyObject,
//   createPrivateKey,
//   createPublicKey,
// } = require('internal/crypto/keys');

// const generateKeyPair = promisify(_generateKeyPair);

// function verifyAcceptableEcKeyUse(name, isPublic, usages) {
//   let checkSet;
//   switch (name) {
//     case 'ECDH':
//       checkSet = isPublic ? [] : ['deriveKey', 'deriveBits'];
//       break;
//     case 'ECDSA':
//       checkSet = isPublic ? ['verify'] : ['sign'];
//       break;
//     default:
//       throw lazyDOMException(
//         'The algorithm is not supported', 'NotSupportedError');
//   }
//   if (hasAnyNotIn(usages, checkSet)) {
//     throw lazyDOMException(
//       `Unsupported key usage for a ${name} key`,
//       'SyntaxError');
//   }
// }

function createECPublicKeyRaw(
  namedCurve: NamedCurve,
  keyData: ArrayBuffer
): PublicKeyObject {
  const handle = NativeQuickCrypto.createKeyObjectHandle();
  if (!handle.initECRaw(kNamedCurveAliases[namedCurve], keyData)) {
    throw new Error('Invalid keyData');
  }

  return new PublicKeyObject(handle);
}

// async function ecGenerateKey(algorithm, extractable, keyUsages) {
//   const { name, namedCurve } = algorithm;

//   if (!ArrayPrototypeIncludes(ObjectKeys(kNamedCurveAliases), namedCurve)) {
//     throw lazyDOMException(
//       'Unrecognized namedCurve',
//       'NotSupportedError');
//   }

//   const usageSet = new SafeSet(keyUsages);
//   switch (name) {
//     case 'ECDSA':
//       if (hasAnyNotIn(usageSet, ['sign', 'verify'])) {
//         throw lazyDOMException(
//           'Unsupported key usage for an ECDSA key',
//           'SyntaxError');
//       }
//       break;
//     case 'ECDH':
//       if (hasAnyNotIn(usageSet, ['deriveKey', 'deriveBits'])) {
//         throw lazyDOMException(
//           'Unsupported key usage for an ECDH key',
//           'SyntaxError');
//       }
//       // Fall through
//   }

//   const keypair = await generateKeyPair('ec', { namedCurve }).catch((err) => {
//     throw lazyDOMException(
//       'The operation failed for an operation-specific reason',
//       { name: 'OperationError', cause: err });
//   });

//   let publicUsages;
//   let privateUsages;
//   switch (name) {
//     case 'ECDSA':
//       publicUsages = getUsagesUnion(usageSet, 'verify');
//       privateUsages = getUsagesUnion(usageSet, 'sign');
//       break;
//     case 'ECDH':
//       publicUsages = [];
//       privateUsages = getUsagesUnion(usageSet, 'deriveKey', 'deriveBits');
//       break;
//   }

//   const keyAlgorithm = { name, namedCurve };

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

export function ecExportKey(key: CryptoKey, format: KWebCryptoKeyFormat) {
  return NativeQuickCrypto.ecKeyExport(format, key.keyObject.handle);
}

export function ecImportKey(
  format: ImportFormat,
  keyData: BufferLike,
  algorithm: SubtleAlgorithm,
  extractable: boolean,
  keyUsages: KeyUsage[]
) {
  const { name, namedCurve } = algorithm;

  // if (!ArrayPrototypeIncludes(ObjectKeys(kNamedCurveAliases), namedCurve)) {
  //   throw lazyDOMException('Unrecognized namedCurve', 'NotSupportedError');
  // }

  let keyObject;
  // const usagesSet = new SafeSet(keyUsages);
  switch (format) {
    // case 'spki': {
    //   // verifyAcceptableEcKeyUse(name, true, usagesSet);
    //   try {
    //     keyObject = createPublicKey({
    //       key: keyData,
    //       format: 'der',
    //       type: 'spki',
    //     });
    //   } catch (err) {
    //     throw new Error(`Invalid keyData: ${err}`);
    //   }
    //   break;
    // }
    // case 'pkcs8': {
    //   // verifyAcceptableEcKeyUse(name, false, usagesSet);
    //   try {
    //     keyObject = createPrivateKey({
    //       key: keyData,
    //       format: 'der',
    //       type: 'pkcs8',
    //     });
    //   } catch (err) {
    //     throw new Error(`Invalid keyData ${err}`);
    //   }
    //   break;
    // }
    // case 'jwk': {
    //   if (!keyData.kty) throw lazyDOMException('Invalid keyData', 'DataError');
    //   if (keyData.kty !== 'EC')
    //     throw lazyDOMException('Invalid JWK "kty" Parameter', 'DataError');
    //   if (keyData.crv !== namedCurve)
    //     throw lazyDOMException(
    //       'JWK "crv" does not match the requested algorithm',
    //       'DataError'
    //     );

    //   verifyAcceptableEcKeyUse(name, keyData.d === undefined, usagesSet);

    //   if (usagesSet.size > 0 && keyData.use !== undefined) {
    //     const checkUse = name === 'ECDH' ? 'enc' : 'sig';
    //     if (keyData.use !== checkUse)
    //       throw lazyDOMException('Invalid JWK "use" Parameter', 'DataError');
    //   }

    //   validateKeyOps(keyData.key_ops, usagesSet);

    //   if (
    //     keyData.ext !== undefined &&
    //     keyData.ext === false &&
    //     extractable === true
    //   ) {
    //     throw lazyDOMException(
    //       'JWK "ext" Parameter and extractable mismatch',
    //       'DataError'
    //     );
    //   }

    //   if (algorithm.name === 'ECDSA' && keyData.alg !== undefined) {
    //     let algNamedCurve;
    //     switch (keyData.alg) {
    //       case 'ES256':
    //         algNamedCurve = 'P-256';
    //         break;
    //       case 'ES384':
    //         algNamedCurve = 'P-384';
    //         break;
    //       case 'ES512':
    //         algNamedCurve = 'P-521';
    //         break;
    //     }
    //     if (algNamedCurve !== namedCurve)
    //       throw lazyDOMException(
    //         'JWK "alg" does not match the requested algorithm',
    //         'DataError'
    //       );
    //   }

    //   const handle = new KeyObjectHandle();
    //   const type = handle.initJwk(keyData, namedCurve);
    //   if (type === undefined)
    //     throw lazyDOMException('Invalid JWK', 'DataError');
    //   keyObject =
    //     type === kKeyTypePrivate
    //       ? new PrivateKeyObject(handle)
    //       : new PublicKeyObject(handle);
    //   break;
    // }
    case 'raw': {
      // verifyAcceptableEcKeyUse(name, true, usagesSet);
      let buffer = bufferLikeToArrayBuffer(keyData);
      keyObject = createECPublicKeyRaw(namedCurve, buffer);
      break;
    }
    default: {
      throw new Error('Unknown format');
    }
  }

  switch (algorithm.name) {
    case 'ECDSA':
    // Fall through
    case 'ECDH':
      // if (keyObject.asymmetricKeyType !== 'ec')
      //   throw new Error('Invalid key type');
      break;
  }

  // if (!keyObject[kHandle].checkEcKeyData()) {
  //   throw new Error('Invalid keyData');
  // }

  // const { namedCurve: checkNamedCurve } = keyObject[kHandle].keyDetail({});
  // if (kNamedCurveAliases[namedCurve] !== checkNamedCurve)
  //   throw new Error('Named curve mismatch');

  return new CryptoKey(keyObject, { name, namedCurve }, keyUsages, extractable);
}

// function ecdsaSignVerify(key, data, { name, hash }, signature) {
//   const mode = signature === undefined ? kSignJobModeSign : kSignJobModeVerify;
//   const type = mode === kSignJobModeSign ? 'private' : 'public';

//   if (key.type !== type)
//     throw lazyDOMException(`Key must be a ${type} key`, 'InvalidAccessError');

//   const hashname = normalizeHashName(hash.name);

//   return jobPromise(() => new SignJob(
//     kCryptoJobAsync,
//     mode,
//     key[kKeyObject][kHandle],
//     undefined,
//     undefined,
//     undefined,
//     data,
//     hashname,
//     undefined,  // Salt length, not used with ECDSA
//     undefined,  // PSS Padding, not used with ECDSA
//     kSigEncP1363,
//     signature));
// }

module.exports = {
  // ecExportKey,
  ecImportKey,
  // ecGenerateKey,
  // ecdsaSignVerify,
};
