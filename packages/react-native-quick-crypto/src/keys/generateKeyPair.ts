// import { ed25519 } from '../ed25519';
// import {
//   kEmptyObject,
//   validateFunction,
//   type CryptoKeyPair,
//   type GenerateKeyPairCallback,
//   type GenerateKeyPairOptions,
//   type GenerateKeyPairPromiseReturn,
//   type GenerateKeyPairReturn,
//   type KeyPairGenConfig,
//   type KeyPairType,
// } from '../utils';
// import { parsePrivateKeyEncoding, parsePublicKeyEncoding } from './utils';

// export const generateKeyPair = (
//   type: KeyPairType,
//   options: GenerateKeyPairOptions,
//   callback: GenerateKeyPairCallback,
// ): void => {
//   validateFunction(callback);
//   internalGenerateKeyPair(true, type, options, callback);
// };

// // Promisify generateKeyPair
// // (attempted to use util.promisify, to no avail)
// export const generateKeyPairPromise = (
//   type: KeyPairType,
//   options: GenerateKeyPairOptions,
// ): Promise<GenerateKeyPairPromiseReturn> => {
//   return new Promise((resolve, reject) => {
//     generateKeyPair(type, options, (err, publicKey, privateKey) => {
//       if (err) {
//         reject([err, undefined]);
//       } else {
//         resolve([undefined, { publicKey, privateKey }]);
//       }
//     });
//   });
// };

// // generateKeyPairSync
// export function generateKeyPairSync(type: KeyPairType): CryptoKeyPair;
// export function generateKeyPairSync(
//   type: KeyPairType,
//   options: GenerateKeyPairOptions,
// ): CryptoKeyPair;
// export function generateKeyPairSync(
//   type: KeyPairType,
//   options?: GenerateKeyPairOptions,
// ): CryptoKeyPair {
//   const [err, publicKey, privateKey] = internalGenerateKeyPair(
//     false,
//     type,
//     options,
//     undefined,
//   )!;

//   if (err) {
//     throw err;
//   }

//   return {
//     publicKey,
//     privateKey,
//   };
// }

// function parseKeyPairEncoding(
//   keyType: string,
//   options: GenerateKeyPairOptions = kEmptyObject,
// ): KeyPairGenConfig {
//   const { publicKeyEncoding, privateKeyEncoding } = options;

//   let publicFormat, publicType;
//   if (publicKeyEncoding == null) {
//     publicFormat = publicType = -1;
//   } else if (typeof publicKeyEncoding === 'object') {
//     ({ format: publicFormat, type: publicType } = parsePublicKeyEncoding(
//       publicKeyEncoding,
//       keyType,
//       'publicKeyEncoding',
//     ));
//   } else {
//     throw new Error(
//       'Invalid argument options.publicKeyEncoding',
//       publicKeyEncoding,
//     );
//   }

//   let privateFormat, privateType, cipher, passphrase;
//   if (privateKeyEncoding == null) {
//     privateFormat = privateType = -1;
//   } else if (typeof privateKeyEncoding === 'object') {
//     ({
//       format: privateFormat,
//       type: privateType,
//       cipher,
//       passphrase,
//     } = parsePrivateKeyEncoding(
//       privateKeyEncoding,
//       keyType,
//       'privateKeyEncoding',
//     ));
//   } else {
//     throw new Error(
//       'Invalid argument options.privateKeyEncoding',
//       publicKeyEncoding as ErrorOptions,
//     );
//   }

//   return {
//     publicFormat,
//     publicType,
//     privateFormat,
//     privateType,
//     cipher,
//     passphrase,
//   };
// }

// function internalGenerateKeyPair(
//   isAsync: boolean,
//   type: KeyPairType,
//   options: GenerateKeyPairOptions | undefined,
//   callback: GenerateKeyPairCallback | undefined,
// ): GenerateKeyPairReturn | void {
//   const encoding = parseKeyPairEncoding(type, options);

//   switch (type) {
//     case 'ed25519':
//     case 'ed448':
//     case 'x25519':
//     case 'x448': {
//       return ed25519.utils.generateKeyPair(isAsync, type, encoding, callback);
//     }
//     default:
//     // Fall through
//   }

//   const err = new Error(`
//     Invalid Argument options: '${type}' scheme not supported for
//     generateKeyPair(). Currently not all encryption methods are supported in
//     this library.  Check docs/implementation_coverage.md for status.
//   `);
//   return [err, undefined, undefined];
// }
