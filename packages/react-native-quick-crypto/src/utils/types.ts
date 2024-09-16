import { type Buffer } from '@craftzdog/react-native-buffer';
import { type Buffer as SBuffer } from 'safe-buffer';
import { type CipherKey } from 'crypto'; // @types/node

export type ArrayBufferView = TypedArray | DataView | ArrayBufferLike | Buffer;

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

export type BufferLike = ArrayBuffer | Buffer | SBuffer | ArrayBufferView;

export type BinaryLike =
  | string
  | ArrayBuffer
  | Buffer
  | SBuffer
  | TypedArray
  | DataView;

export type BinaryLikeNode = CipherKey | BinaryLike;

export type DigestAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512';

export type HashAlgorithm = DigestAlgorithm | 'SHA-224' | 'RIPEMD-160';

export type RSAKeyPairAlgorithm = 'RSASSA-PKCS1-v1_5' | 'RSA-PSS' | 'RSA-OAEP';

export type ECKeyPairAlgorithm = 'ECDSA' | 'ECDH';

export type CFRGKeyPairAlgorithm = 'Ed25519' | 'Ed448' | 'X25519' | 'X448';

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

export type AsymmetricKeyType = 'rsa' | 'rsa-pss' | 'dsa' | 'ec';

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
