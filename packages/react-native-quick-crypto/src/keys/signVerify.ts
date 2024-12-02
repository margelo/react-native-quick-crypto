// import { KeyObject, PublicKeyObject, PrivateKeyObject } from '.';
// import { ed25519 } from '../ed25519';
// import type {
//   BinaryLike,
//   BinaryLikeNode,
//   SignCallback,
//   VerifyCallback,
// } from '../utils';

// export function sign(
//   algorithm: string | null | undefined,
//   data: BinaryLike,
//   key: BinaryLikeNode | KeyObject,
//   callback: SignCallback,
// ): ArrayBuffer {
//   console.log('sign  ', algorithm, data, key, callback);
//   return new ArrayBuffer(32);
// }

// export function verify(
//   algorithm: string | null | undefined,
//   data: BinaryLike,
//   key: BinaryLikeNode | KeyObject,
//   signature: ArrayBuffer,
//   callback: VerifyCallback,
// ): boolean {
//   if (!algorithm) {
//     if (key instanceof PublicKeyObject) {
//       switch (key.asymmetricKeyType) {
//         case 'ed25519':
//         case 'ed448':
//         case 'x25519':
//         case 'x448': {
//           return ed25519.verify(signature, data, key);
//         }
//     }
//   }
//   throw new Error('Verify not implemented', algorithm, data, key, signature, callback);
// }
