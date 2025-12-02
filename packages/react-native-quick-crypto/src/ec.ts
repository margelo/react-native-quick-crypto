import { NitroModules } from 'react-native-nitro-modules';
import type { EcKeyPair } from './specs/ecKeyPair.nitro';
import type { KeyObjectHandle } from './specs/keyObjectHandle.nitro';
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
  NamedCurve,
  GenerateKeyPairOptions,
  KeyPairGenConfig,
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
import { Buffer } from 'buffer';

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

  // Handle JWK format
  if (format === 'jwk') {
    const jwk = keyData as JWK;

    // Validate JWK
    if (jwk.kty !== 'EC') {
      throw lazyDOMException('Invalid JWK "kty" Parameter', 'DataError');
    }

    if (jwk.crv !== namedCurve) {
      throw lazyDOMException(
        'JWK "crv" does not match the requested algorithm',
        'DataError',
      );
    }

    // Check use parameter if present
    if (jwk.use !== undefined) {
      const expectedUse = name === 'ECDH' ? 'enc' : 'sig';
      if (jwk.use !== expectedUse) {
        throw lazyDOMException('Invalid JWK "use" Parameter', 'DataError');
      }
    }

    // Check alg parameter if present
    if (jwk.alg !== undefined) {
      let expectedAlg: string | undefined;

      if (name === 'ECDSA') {
        // Map namedCurve to expected ECDSA algorithm
        expectedAlg =
          namedCurve === 'P-256'
            ? 'ES256'
            : namedCurve === 'P-384'
              ? 'ES384'
              : namedCurve === 'P-521'
                ? 'ES512'
                : undefined;
      } else if (name === 'ECDH') {
        // ECDH uses ECDH-ES algorithm
        expectedAlg = 'ECDH-ES';
      }

      if (expectedAlg && jwk.alg !== expectedAlg) {
        throw lazyDOMException(
          'JWK "alg" does not match the requested algorithm',
          'DataError',
        );
      }
    }

    // Import using C++ layer
    const handle =
      NitroModules.createHybridObject<KeyObjectHandle>('KeyObjectHandle');
    const keyType = handle.initJwk(jwk, namedCurve as NamedCurve);

    if (keyType === undefined) {
      throw lazyDOMException('Invalid JWK', 'DataError');
    }

    // Create the appropriate KeyObject based on type
    let keyObject: KeyObject;
    if (keyType === 1) {
      keyObject = new PublicKeyObject(handle);
    } else if (keyType === 2) {
      keyObject = new PrivateKeyObject(handle);
    } else {
      throw lazyDOMException(
        'Unexpected key type from JWK import',
        'DataError',
      );
    }

    return new CryptoKey(keyObject, algorithm, keyUsages, extractable);
  }

  // Handle binary formats (spki, pkcs8, raw)
  if (format !== 'spki' && format !== 'pkcs8' && format !== 'raw') {
    throw lazyDOMException(
      `Unsupported format: ${format}`,
      'NotSupportedError',
    );
  }

  // Determine expected key type based on format
  const expectedKeyType =
    format === 'spki' || format === 'raw' ? 'public' : 'private';

  // Validate usages for the key type
  const isPublicKey = expectedKeyType === 'public';
  let validUsages: KeyUsage[];

  if (name === 'ECDSA') {
    validUsages = isPublicKey ? ['verify'] : ['sign'];
  } else if (name === 'ECDH') {
    validUsages = isPublicKey ? [] : ['deriveKey', 'deriveBits'];
  } else {
    throw lazyDOMException('Unsupported algorithm', 'NotSupportedError');
  }

  if (hasAnyNotIn(keyUsages, validUsages)) {
    throw lazyDOMException(
      `Unsupported key usage for a ${name} key`,
      'SyntaxError',
    );
  }

  // Convert keyData to ArrayBuffer
  const keyBuffer = bufferLikeToArrayBuffer(keyData as BufferLike);

  // Create KeyObject directly using the appropriate format
  let keyObject: KeyObject;

  if (format === 'raw') {
    // Raw format is only for public keys - use specialized EC raw import
    const handle =
      NitroModules.createHybridObject<KeyObjectHandle>('KeyObjectHandle');
    const curveAlias =
      kNamedCurveAliases[namedCurve as keyof typeof kNamedCurveAliases];
    if (!handle.initECRaw(curveAlias, keyBuffer)) {
      throw lazyDOMException('Failed to import EC raw key', 'DataError');
    }
    keyObject = new PublicKeyObject(handle);
  } else {
    // Use standard DER import for spki/pkcs8
    keyObject = KeyObject.createKeyObject(
      expectedKeyType,
      keyBuffer,
      KFormatType.DER,
      format === 'spki' ? KeyEncoding.SPKI : KeyEncoding.PKCS8,
    );
  }

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
    KFormatType.DER,
    KeyEncoding.SPKI,
  ) as PublicKeyObject;
  const publicKey = new CryptoKey(
    pub,
    keyAlgorithm as SubtleAlgorithm,
    publicUsages,
    true,
  );

  // All keys are now exported in PKCS8 format for consistency
  const priv = KeyObject.createKeyObject(
    'private',
    privateKeyData,
    KFormatType.DER,
    KeyEncoding.PKCS8,
  ) as PrivateKeyObject;
  const privateKey = new CryptoKey(
    priv,
    keyAlgorithm as SubtleAlgorithm,
    privateUsages,
    extractable,
  );

  return { publicKey, privateKey };
}

export async function ec_generateKeyPairNode(
  options: GenerateKeyPairOptions | undefined,
  encoding: KeyPairGenConfig,
): Promise<{
  publicKey: PublicKeyObject | Buffer | string;
  privateKey: PrivateKeyObject | Buffer | string;
}> {
  if (!options) {
    throw new Error('Options are required for EC key generation');
  }

  const { namedCurve } = options as { namedCurve?: string };

  if (
    !namedCurve ||
    !kNamedCurveAliases[namedCurve as keyof typeof kNamedCurveAliases]
  ) {
    throw new Error(`Invalid or unsupported named curve: ${namedCurve}`);
  }

  const keyPair = await ec_generateKeyPair('ECDSA', namedCurve, true, [
    'sign',
    'verify',
  ]);

  // ec_generateKeyPair returns CryptoKey objects
  const pubCryptoKey = keyPair.publicKey as CryptoKey;
  const privCryptoKey = keyPair.privateKey as CryptoKey;

  const {
    publicFormat,
    publicType,
    privateFormat,
    privateType,
    cipher,
    passphrase,
  } = encoding;

  let publicKey: PublicKeyObject | Buffer | string;
  let privateKey: PrivateKeyObject | Buffer | string;

  if (publicFormat === -1) {
    publicKey = pubCryptoKey.keyObject as PublicKeyObject;
  } else {
    const format =
      publicFormat === KFormatType.PEM ? KFormatType.PEM : KFormatType.DER;
    const keyEncoding =
      publicType === KeyEncoding.SPKI ? KeyEncoding.SPKI : KeyEncoding.SPKI;
    const exported = pubCryptoKey.keyObject.handle.exportKey(
      format,
      keyEncoding,
    );
    // For PEM format, convert ArrayBuffer to string; for DER, keep as ArrayBuffer
    if (format === KFormatType.PEM) {
      publicKey = Buffer.from(new Uint8Array(exported)).toString('utf-8');
    } else {
      // Return raw ArrayBuffer for DER format
      publicKey = Buffer.from(new Uint8Array(exported));
    }
  }

  if (privateFormat === -1) {
    privateKey = privCryptoKey.keyObject as PrivateKeyObject;
  } else {
    const format =
      privateFormat === KFormatType.PEM ? KFormatType.PEM : KFormatType.DER;
    const keyEncoding =
      privateType === KeyEncoding.PKCS8
        ? KeyEncoding.PKCS8
        : privateType === KeyEncoding.SEC1
          ? KeyEncoding.SEC1
          : KeyEncoding.PKCS8;
    const exported = privCryptoKey.keyObject.handle.exportKey(
      format,
      keyEncoding,
      cipher,
      passphrase,
    );
    // For PEM format, convert ArrayBuffer to string; for DER, keep as ArrayBuffer
    if (format === KFormatType.PEM) {
      privateKey = Buffer.from(new Uint8Array(exported)).toString('utf-8');
    } else {
      // Return raw ArrayBuffer for DER format
      privateKey = Buffer.from(new Uint8Array(exported));
    }
  }

  return { publicKey, privateKey };
}
