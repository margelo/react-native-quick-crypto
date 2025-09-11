import { NitroModules } from 'react-native-nitro-modules';
import type { EcKeyPair } from './specs/ecKeyPair.nitro';
import {
  CryptoKey,
  KeyObject,
  PublicKeyObject,
  PrivateKeyObject,
} from './keys';
import type {
  CryptoKeyPair,
  KeyPairOptions,
  KeyUsage,
  SubtleAlgorithm,
  BufferLike,
  BinaryLike,
  JWK,
  ImportFormat,
} from './utils/types';
import {
  bufferLikeToArrayBuffer,
  getUsagesUnion,
  hasAnyNotIn,
  kNamedCurveAliases,
  lazyDOMException,
  normalizeHashName,
  HashContext,
  KeyEncoding,
  KFormatType,
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
//   keyDataBuffer: ArrayBuffer,
// ): PublicKeyObject {
//   if (!namedCurve) {
//     throw new Error('Invalid namedCurve');
//   }
//   const handle = NitroModules.createHybridObject(
//     'KeyObjectHandle',
//   ) as KeyObjectHandle;

//   if (!handle.initECRaw(kNamedCurveAliases[namedCurve], keyDataBuffer)) {
//     console.log('keyData', ab2str(keyDataBuffer));
//     throw new Error('Invalid keyData 1');
//   }

//   return new PublicKeyObject(handle);
// }

// // Node API
// export function ec_exportKey(key: CryptoKey, format: KeyFormat): ArrayBuffer {
//   return ec.native.exportKey(format, key.keyObject.handle);
// }

// Node API
export function ecImportKey(
  format: ImportFormat,
  keyData: BufferLike | BinaryLike | JWK,
  algorithm: SubtleAlgorithm,
  extractable: boolean,
  keyUsages: KeyUsage[],
): CryptoKey {
  const { name, namedCurve } = algorithm;

  if (
    !namedCurve ||
    !kNamedCurveAliases[namedCurve as keyof typeof kNamedCurveAliases]
  ) {
    throw lazyDOMException('Unrecognized namedCurve', 'NotSupportedError');
  }

  if (format !== 'spki' && format !== 'pkcs8' && format !== 'raw') {
    throw lazyDOMException(
      `Unsupported format: ${format}`,
      'NotSupportedError',
    );
  }

  // Handle JWK format separately
  if (typeof keyData === 'object' && 'kty' in keyData) {
    throw lazyDOMException('JWK format not yet supported', 'NotSupportedError');
  }

  // Convert keyData to ArrayBuffer
  const keyBuffer = bufferLikeToArrayBuffer(keyData as BufferLike);

  // Create EC instance with the curve
  const ec = new Ec(namedCurve);

  // Import the key using Nitro module
  ec.native.importKey(
    format === 'raw' ? 'der' : format, // Convert raw to der for now
    keyBuffer,
    name,
    extractable,
    keyUsages,
  );

  // Create a KeyObject wrapper for the imported key
  // Use the EC instance's key data to create a proper KeyObject
  const privateKeyData = ec.native.getPrivateKey();
  const keyObject = new KeyObject('private', privateKeyData);

  // Create and return CryptoKey
  return new CryptoKey(keyObject, algorithm, keyUsages, extractable);
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
}

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

// Node API
export const ecdsaSignVerify = (
  key: CryptoKey,
  data: BufferLike,
  { hash }: SubtleAlgorithm,
  signature?: BufferLike,
): ArrayBuffer | boolean => {
  const isSign = signature === undefined;
  const expectedKeyType = isSign ? 'private' : 'public';

  if (key.type !== expectedKeyType) {
    throw lazyDOMException(
      `Key must be a ${expectedKeyType} key`,
      'InvalidAccessError',
    );
  }

  const hashName = typeof hash === 'string' ? hash : hash?.name;

  if (!hashName) {
    throw lazyDOMException(
      'Hash algorithm is required for ECDSA',
      'InvalidAccessError',
    );
  }

  // Normalize hash algorithm name to WebCrypto format for C++ layer
  const normalizedHashName = normalizeHashName(hashName, HashContext.WebCrypto);

  // Create EC instance with the curve from the key
  const namedCurve = key.algorithm.namedCurve!;
  const ec = new Ec(namedCurve);

  // Extract and import the actual key data from the CryptoKey
  // Export in DER format with appropriate encoding
  const encoding =
    key.type === 'private' ? KeyEncoding.PKCS8 : KeyEncoding.SPKI;
  const keyData = key.keyObject.handle.exportKey(KFormatType.DER, encoding);
  const keyBuffer = bufferLikeToArrayBuffer(keyData);
  ec.native.importKey(
    'der',
    keyBuffer,
    key.algorithm.name!,
    key.extractable,
    key.usages,
  );

  const dataBuffer = bufferLikeToArrayBuffer(data);

  if (isSign) {
    // Sign operation
    return ec.native.sign(dataBuffer, normalizedHashName);
  } else {
    // Verify operation
    const signatureBuffer = bufferLikeToArrayBuffer(signature!);
    return ec.native.verify(dataBuffer, signatureBuffer, normalizedHashName);
  }
};

// Node API

export async function ec_generateKeyPair(
  name: string,
  namedCurve: string,
  extractable: boolean,
  keyUsages: KeyUsage[],
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  _options?: KeyPairOptions, // TODO: Implement format options support
): Promise<CryptoKeyPair> {
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

  // Export keys directly from the EC key pair using the internal EVP_PKEY
  // These methods export in DER format (SPKI for public, PKCS8 for private)
  const publicKeyData = ec.native.getPublicKey();
  const privateKeyData = ec.native.getPrivateKey();

  const pub = KeyObject.createKeyObject(
    'public',
    publicKeyData,
    'der',
    'spki',
  ) as PublicKeyObject;
  const publicKey = new CryptoKey(
    pub,
    keyAlgorithm as SubtleAlgorithm,
    publicUsages,
    true,
  );

  // All keys are now exported in PKCS8 format for consistency
  const privateEncoding = 'pkcs8';
  const priv = KeyObject.createKeyObject(
    'private',
    privateKeyData,
    'der',
    privateEncoding as 'pkcs8' | 'spki' | 'sec1',
  ) as PrivateKeyObject;
  const privateKey = new CryptoKey(
    priv,
    keyAlgorithm as SubtleAlgorithm,
    privateUsages,
    extractable,
  );

  return { publicKey, privateKey };
}
