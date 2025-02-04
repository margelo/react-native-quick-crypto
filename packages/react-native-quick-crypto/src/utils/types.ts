import type { Buffer as CraftzdogBuffer } from '@craftzdog/react-native-buffer';
import type { Buffer as SafeBuffer } from 'safe-buffer';
import type { CipherKey } from 'crypto'; // @types/node
import type { KeyObjectHandle } from '../specs/keyObjectHandle.nitro';

export type ABV = TypedArray | DataView | ArrayBufferLike | CraftzdogBuffer;

export type TypedArray =
  | Uint8Array
  | Uint8ClampedArray
  | Uint16Array
  | Uint32Array
  | Int8Array
  | Int16Array
  | Int32Array
  | Float32Array
  | Float64Array;

export type RandomCallback<T> = (err: Error | null, value: T) => void;

export type BufferLike =
  | ArrayBuffer
  | CraftzdogBuffer
  | SafeBuffer
  | ArrayBufferView;

export type BinaryLike =
  | string
  | ArrayBuffer
  | CraftzdogBuffer
  | SafeBuffer
  | TypedArray
  | DataView;

export type BinaryLikeNode = CipherKey | BinaryLike;

export type DigestAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512';

export type HashAlgorithm = DigestAlgorithm | 'SHA-224' | 'RIPEMD-160';

export type RSAKeyPairAlgorithm = 'RSASSA-PKCS1-v1_5' | 'RSA-PSS' | 'RSA-OAEP';

export type ECKeyPairAlgorithm = 'ECDSA' | 'ECDH';

export type CFRGKeyPairAlgorithm = 'Ed25519' | 'Ed448' | 'X25519' | 'X448';
export type CFRGKeyPairType = 'ed25519' | 'ed448' | 'x25519' | 'x448';

export type KeyPairAlgorithm =
  | RSAKeyPairAlgorithm
  | ECKeyPairAlgorithm
  | CFRGKeyPairAlgorithm;

export type AESAlgorithm = 'AES-CTR' | 'AES-CBC' | 'AES-GCM' | 'AES-KW';

export type SecretKeyAlgorithm = 'HMAC' | AESAlgorithm;

export type SignVerifyAlgorithm =
  | 'RSASSA-PKCS1-v1_5'
  | 'RSA-PSS'
  | 'ECDSA'
  | 'HMAC'
  | 'Ed25519'
  | 'Ed448';

export type DeriveBitsAlgorithm =
  | 'PBKDF2'
  | 'HKDF'
  | 'ECDH'
  | 'X25519'
  | 'X448';

export type EncryptDecryptAlgorithm =
  | 'RSA-OAEP'
  | 'AES-CTR'
  | 'AES-CBC'
  | 'AES-GCM';

export type AnyAlgorithm =
  | DigestAlgorithm
  | HashAlgorithm
  | KeyPairAlgorithm
  | SecretKeyAlgorithm
  | SignVerifyAlgorithm
  | DeriveBitsAlgorithm
  | EncryptDecryptAlgorithm
  | AESAlgorithm
  | 'PBKDF2'
  | 'HKDF'
  | 'unknown';

export type NamedCurve = 'P-256' | 'P-384' | 'P-521';

export type SubtleAlgorithm = {
  name: AnyAlgorithm;
  salt?: string;
  iterations?: number;
  hash?: HashAlgorithm;
  namedCurve?: NamedCurve;
  length?: number;
  modulusLength?: number;
  publicExponent?: number | Uint8Array;
};

export type KeyPairType = CFRGKeyPairType;

export type KeyUsage =
  | 'encrypt'
  | 'decrypt'
  | 'sign'
  | 'verify'
  | 'deriveKey'
  | 'deriveBits'
  | 'wrapKey'
  | 'unwrapKey';

// On node this value is defined on the native side, for now I'm just creating it here in JS
// TODO(osp) move this into native side to make sure they always match
export enum KFormatType {
  kKeyFormatDER,
  kKeyFormatPEM,
  kKeyFormatJWK,
}

// Same as KFormatType, this enum needs to be defined on the native side
export enum KeyType {
  Secret,
  Public,
  Private,
}

export enum KeyEncoding {
  kKeyEncodingPKCS1,
  kKeyEncodingPKCS8,
  kKeyEncodingSPKI,
  kKeyEncodingSEC1,
}

export type KeyPairGenConfig = {
  publicFormat?: KFormatType;
  publicType?: KeyEncoding;
  privateFormat?: KFormatType;
  privateType?: KeyEncoding;
  cipher?: string;
  passphrase?: ArrayBuffer;
};

export type AsymmetricKeyType =
  // 'rsa' |
  // 'rsa-pss' |
  // 'dsa' |
  // 'ec' |
  // 'dh' |
  CFRGKeyPairType;

type JWKkty = 'AES' | 'RSA' | 'EC' | 'oct';
type JWKuse = 'sig' | 'enc';

export interface JWK {
  kty?: JWKkty;
  use?: JWKuse;
  key_ops?: KeyUsage[];
  alg?: string; // TODO: enumerate these (RFC-7517)
  crv?: string;
  kid?: string;
  x5u?: string;
  x5c?: string[];
  x5t?: string;
  'x5t#256'?: string;
  n?: string;
  e?: string;
  d?: string;
  p?: string;
  q?: string;
  x?: string;
  y?: string;
  k?: string;
  dp?: string;
  dq?: string;
  qi?: string;
  ext?: boolean;
}

export type KTypePrivate = 'pkcs1' | 'pkcs8' | 'sec1';
export type KTypePublic = 'pkcs1' | 'spki';
export type KType = KTypePrivate | KTypePublic;

export type KFormat = 'der' | 'pem' | 'jwk';

export type DSAEncoding = 'der' | 'ieee-p1363';

export type EncodingOptions = {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  key?: any;
  type?: KType;
  encoding?: string;
  dsaEncoding?: DSAEncoding;
  format?: KFormat;
  padding?: number;
  cipher?: string;
  passphrase?: BinaryLike;
  saltLength?: number;
  oaepHash?: string;
  oaepLabel?: BinaryLike;
};

export interface KeyDetail {
  length?: number;
  publicExponent?: number;
  modulusLength?: number;
  hashAlgorithm?: string;
  mgf1HashAlgorithm?: string;
  saltLength?: number;
  namedCurve?: string;
}

export type GenerateKeyPairOptions = {
  modulusLength?: number; // Key size in bits (RSA, DSA).
  publicExponent?: number; // Public exponent (RSA). Default: 0x10001.
  hashAlgorithm?: string; // Name of the message digest (RSA-PSS).
  mgf1HashAlgorithm?: string; // string Name of the message digest used by MGF1 (RSA-PSS).
  saltLength?: number; // Minimal salt length in bytes (RSA-PSS).
  divisorLength?: number; // Size of q in bits (DSA).
  namedCurve?: string; // Name of the curve to use (EC).
  prime?: CraftzdogBuffer; // The prime parameter (DH).
  primeLength?: number; // Prime length in bits (DH).
  generator?: number; // Custom generator (DH). Default: 2.
  groupName?: string; // Diffie-Hellman group name (DH). See crypto.getDiffieHellman().
  publicKeyEncoding?: EncodingOptions; // See keyObject.export().
  privateKeyEncoding?: EncodingOptions; // See keyObject.export().
  paramEncoding?: string;
  hash?: string;
  mgf1Hash?: string;
};

// Note: removed CryptoKey class from this type (from 0.x) because Nitro doesn't
//       handle custom JS objects.  We might need to make it a JS object.
export type KeyPairKey = ArrayBuffer | KeyObjectHandle | undefined;

export type GenerateKeyPairReturn = [
  error?: Error,
  privateKey?: KeyPairKey,
  publicKey?: KeyPairKey,
];

export type GenerateKeyPairCallback = (
  error?: Error,
  publicKey?: KeyPairKey,
  privateKey?: KeyPairKey,
) => GenerateKeyPairReturn | void;

export type KeyPair = {
  publicKey?: KeyPairKey;
  privateKey?: KeyPairKey;
};

export type GenerateKeyPairPromiseReturn = [error?: Error, keypair?: KeyPair];

export type CryptoKeyPair = {
  publicKey: KeyPairKey;
  privateKey: KeyPairKey;
};

export enum KeyVariant {
  RSA_SSA_PKCS1_v1_5,
  RSA_PSS,
  RSA_OAEP,
  DSA,
  EC,
  NID,
  DH,
}

export type SignCallback = (err: Error | null, signature?: ArrayBuffer) => void;

export type VerifyCallback = (err: Error | null, valid?: boolean) => void;

export type BinaryToTextEncoding = 'base64' | 'base64url' | 'hex' | 'binary';
export type CharacterEncoding = 'utf8' | 'utf-8' | 'utf16le' | 'latin1';
export type LegacyCharacterEncoding = 'ascii' | 'binary' | 'ucs2' | 'ucs-2';
export type Encoding =
  | BinaryToTextEncoding
  | CharacterEncoding
  | LegacyCharacterEncoding
  | 'buffer';
