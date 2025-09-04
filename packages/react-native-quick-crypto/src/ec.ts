import { NitroModules } from 'react-native-nitro-modules';
import {
  PublicKeyObject,
  PrivateKeyObject,
  CryptoKey,
  KeyObject,
} from './keys/classes';
import type { EcKeyPair } from './specs/ecKeyPair.nitro';
import {
  // KeyType,
  // KeyFormat,
  // ab2str,
  // bufferLikeToArrayBuffer,
  // binaryLikeToArrayBuffer,
  getUsagesUnion,
  hasAnyNotIn,
  kNamedCurveAliases,
  lazyDOMException,
  // normalizeHashName,
  // validateKeyOps,
} from './utils';
import type {
  // AnyAlgorithm,
  // BufferLike,
  // BinaryLike,
  CryptoKeyPair,
  // ImportFormat,
  KeyUsage,
  // NamedCurve,
  // JWK,
  SubtleAlgorithm,
  // AsymmetricKeyType,
  // KeyObjectHandle,
} from './utils';

export class Ec {
  native: EcKeyPair;

  constructor(curve: string) {
    this.native = NitroModules.createHybridObject<EcKeyPair>('EcKeyPair');
    this.native.setCurve(curve);
  }

  async generateKeyPair(): Promise<CryptoKeyPair> {
    await this.native.generateKeyPair();
    return {
      publicKey: this.native.getPublicKey(),
      privateKey: this.native.getPrivateKey(),
    };
  }

  generateKeyPairSync(): CryptoKeyPair {
    this.native.generateKeyPairSync();
    return {
      publicKey: this.native.getPublicKey(),
      privateKey: this.native.getPrivateKey(),
    };
  }
}

// function verifyAcceptableEcKeyUse(
//   name: AnyAlgorithm,
//   isPublic: boolean,
//   usages: KeyUsage[],
// ): void {
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
//         'The algorithm is not supported',
//         'NotSupportedError',
//       );
//   }
//   if (hasAnyNotIn(usages, checkSet)) {
//     throw lazyDOMException(
//       `Unsupported key usage for a ${name} key`,
//       'SyntaxError',
//     );
//   }
// }

// function createECPublicKeyRaw(
//   namedCurve: NamedCurve | undefined,
//   keyData: ArrayBuffer,
// ): PublicKeyObject {
//   if (!namedCurve) {
//     throw new Error('Invalid namedCurve');
//   }
//   const handle = NitroModules.createHybridObject(
//     'KeyObjectHandle',
//   ) as KeyObjectHandle;

//   if (!handle.initECRaw(kNamedCurveAliases[namedCurve], keyData)) {
//     console.log('keyData', ab2str(keyData));
//     throw new Error('Invalid keyData 1');
//   }

//   return new PublicKeyObject(handle);
// }

// // Node API
// export function ec_exportKey(key: CryptoKey, format: KeyFormat): ArrayBuffer {
//   return ec.native.exportKey(format, key.keyObject.handle);
// }

// // Node API
// export function ecImportKey(
//   format: ImportFormat,
//   keyData: BufferLike | BinaryLike | JWK,
//   algorithm: SubtleAlgorithm,
//   extractable: boolean,
//   keyUsages: KeyUsage[],
// ): CryptoKey {
//   const { name, namedCurve } = algorithm;

//   // if (!ArrayPrototypeIncludes(ObjectKeys(kNamedCurveAliases), namedCurve)) {
//   //   throw lazyDOMException('Unrecognized namedCurve', 'NotSupportedError');
//   // }

//   let keyObject;
//   // const usagesSet = new SafeSet(keyUsages);
//   switch (format) {
//     // case 'spki': {
//     //   // verifyAcceptableEcKeyUse(name, true, usagesSet);
//     //   try {
//     //     keyObject = createPublicKey({
//     //       key: keyData,
//     //       format: 'der',
//     //       type: 'spki',
//     //     });
//     //   } catch (err) {
//     //     throw new Error(`Invalid keyData 2: ${err}`);
//     //   }
//     //   break;
//     // }
//     // case 'pkcs8': {
//     //   // verifyAcceptableEcKeyUse(name, false, usagesSet);
//     //   try {
//     //     keyObject = createPrivateKey({
//     //       key: keyData,
//     //       format: 'der',
//     //       type: 'pkcs8',
//     //     });
//     //   } catch (err) {
//     //     throw new Error(`Invalid keyData 3 ${err}`);
//     //   }
//     //   break;
//     // }
//     case 'jwk': {
//       const data = keyData as JWK;

//       if (!data.kty) throw lazyDOMException('Invalid keyData 4', 'DataError');
//       if (data.kty !== 'EC')
//         throw lazyDOMException('Invalid JWK "kty" Parameter', 'DataError');
//       if (data.crv !== namedCurve)
//         throw lazyDOMException(
//           'JWK "crv" does not match the requested algorithm',
//           'DataError',
//         );

//       verifyAcceptableEcKeyUse(name, data.d === undefined, keyUsages);

//       if (keyUsages.length > 0 && data.use !== undefined) {
//         const checkUse = name === 'ECDH' ? 'enc' : 'sig';
//         if (data.use !== checkUse)
//           throw lazyDOMException('Invalid JWK "use" Parameter', 'DataError');
//       }

//       validateKeyOps(data.key_ops, keyUsages);

//       if (
//         data.ext !== undefined &&
//         data.ext === false &&
//         extractable === true
//       ) {
//         throw lazyDOMException(
//           'JWK "ext" Parameter and extractable mismatch',
//           'DataError',
//         );
//       }

//       if (algorithm.name === 'ECDSA' && data.alg !== undefined) {
//         let algNamedCurve;
//         switch (data.alg) {
//           case 'ES256':
//             algNamedCurve = 'P-256';
//             break;
//           case 'ES384':
//             algNamedCurve = 'P-384';
//             break;
//           case 'ES512':
//             algNamedCurve = 'P-521';
//             break;
//         }
//         if (algNamedCurve !== namedCurve)
//           throw lazyDOMException(
//             'JWK "alg" does not match the requested algorithm',
//             'DataError',
//           );
//       }

//       const handle = NativeQuickCrypto.webcrypto.createKeyObjectHandle();
//       const type = handle.initJwk(data, namedCurve);
//       if (type === undefined)
//         throw lazyDOMException('Invalid JWK', 'DataError');
//       keyObject =
//         type === KeyType.PRIVATE
//           ? new PrivateKeyObject(handle)
//           : new PublicKeyObject(handle);
//       break;
//     }
//     case 'raw': {
//       const data = keyData as BufferLike | BinaryLike;
//       verifyAcceptableEcKeyUse(name, true, keyUsages);
//       const buffer =
//         typeof data === 'string'
//           ? binaryLikeToArrayBuffer(data)
//           : bufferLikeToArrayBuffer(data);
//       keyObject = createECPublicKeyRaw(namedCurve, buffer);
//       break;
//     }
//     default: {
//       throw new Error(`Unknown EC import format: ${format}`);
//     }
//   }

//   switch (algorithm.name) {
//     case 'ECDSA':
//     // Fall through
//     case 'ECDH':
//       if (keyObject.asymmetricKeyType !== ('ec' as AsymmetricKeyType))
//         throw new Error('Invalid key type');
//       break;
//   }

//   // if (!keyObject[kHandle].checkEcKeyData()) {
//   //   throw new Error('Invalid keyData 5');
//   // }

//   // const { namedCurve: checkNamedCurve } = keyObject[kHandle].keyDetail({});
//   // if (kNamedCurveAliases[namedCurve] !== checkNamedCurve)
//   //   throw new Error('Named curve mismatch');

//   return new CryptoKey(keyObject, { name, namedCurve }, keyUsages, extractable);
// }

// // Node API
// export const ecdsaSignVerify = (
//   key: CryptoKey,
//   data: BufferLike,
//   { hash }: SubtleAlgorithm,
//   signature?: BufferLike,
// ) => {
//   const mode: SignMode =
//     signature === undefined
//       ? SignMode.kSignJobModeSign
//       : SignMode.kSignJobModeVerify;
//   const type = mode === SignMode.kSignJobModeSign ? 'private' : 'public';

//   if (key.type !== type)
//     throw lazyDOMException(`Key must be a ${type} key`, 'InvalidAccessError');

//   const hashname = normalizeHashName(hash);

//   return NativeQuickCrypto.webcrypto.signVerify(
//     mode,
//     key.keyObject.handle,
//     // three undefined args because C++ uses `GetPublicOrPrivateKeyFromJs` & friends
//     undefined,
//     undefined,
//     undefined,
//     bufferLikeToArrayBuffer(data),
//     hashname,
//     undefined, // salt length, not used with ECDSA
//     undefined, // pss padding, not used with ECDSA
//     DSASigEnc.kSigEncP1363,
//     bufferLikeToArrayBuffer(signature || new ArrayBuffer(0)),
//   );
// };

// Node API
export const ec_generateKeyPair = async (
  algorithm: SubtleAlgorithm,
  extractable: boolean,
  keyUsages: KeyUsage[],
): Promise<CryptoKeyPair> => {
  const { name, namedCurve } = algorithm;

  // validation checks
  if (!Object.keys(kNamedCurveAliases).includes(namedCurve || '')) {
    throw lazyDOMException(
      `Unrecognized namedCurve '${namedCurve}'`,
      'NotSupportedError',
    );
  }

  // const usageSet = new SafeSet(keyUsages);
  switch (name) {
    case 'ECDSA':
      if (hasAnyNotIn(keyUsages, ['sign', 'verify'])) {
        throw lazyDOMException(
          'Unsupported key usage for an ECDSA key',
          'SyntaxError',
        );
      }
      break;
    case 'ECDH':
      if (hasAnyNotIn(keyUsages, ['deriveKey', 'deriveBits'])) {
        throw lazyDOMException(
          'Unsupported key usage for an ECDH key',
          'SyntaxError',
        );
      }
    // Fall through
  }

  const ec = new Ec(namedCurve!);
  await ec.generateKeyPair();

  let publicUsages: KeyUsage[] = [];
  let privateUsages: KeyUsage[] = [];
  switch (name) {
    case 'ECDSA':
      publicUsages = getUsagesUnion(keyUsages, 'verify');
      privateUsages = getUsagesUnion(keyUsages, 'sign');
      break;
    case 'ECDH':
      publicUsages = [];
      privateUsages = getUsagesUnion(keyUsages, 'deriveKey', 'deriveBits');
      break;
  }

  const keyAlgorithm = { name, namedCurve: namedCurve! };

  // Create KeyObject instances using the standard createKeyObject method
  const publicKeyData = ec.native.getPublicKey();
  const pub = KeyObject.createKeyObject(
    'public',
    publicKeyData,
  ) as PublicKeyObject;
  const publicKey = new CryptoKey(pub, keyAlgorithm, publicUsages, true);

  const privateKeyData = ec.native.getPrivateKey();
  const priv = KeyObject.createKeyObject(
    'private',
    privateKeyData,
  ) as PrivateKeyObject;
  const privateKey = new CryptoKey(
    priv,
    keyAlgorithm,
    privateUsages,
    extractable,
  );

  return { publicKey, privateKey };
};
