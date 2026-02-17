import type { Buffer as CraftzdogBuffer } from '@craftzdog/react-native-buffer';
import type { Buffer } from 'buffer';
import type { CipherKey } from 'node:crypto'; // @types/node
import type { Buffer as SafeBuffer } from 'safe-buffer';
import type { KeyObjectHandle as KeyObjectHandleType } from '../specs/keyObjectHandle.nitro';
import type { KeyObject, CryptoKey } from '../keys';

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
  | ArrayBufferLike
  | CraftzdogBuffer
  | SafeBuffer
  | ArrayBufferView;

export type BinaryLike =
  | string
  | Buffer
  | ArrayBuffer
  | ArrayBufferLike
  | ArrayBufferView
  | CraftzdogBuffer
  | SafeBuffer
  | TypedArray
  | DataView;

export type BinaryLikeNode = CipherKey | BinaryLike | KeyObject;

export type DigestAlgorithm =
  | 'SHA-1'
  | 'SHA-256'
  | 'SHA-384'
  | 'SHA-512'
  | 'SHA3-256'
  | 'SHA3-384'
  | 'SHA3-512'
  | 'cSHAKE128'
  | 'cSHAKE256';

export type HashAlgorithm = DigestAlgorithm | 'SHA-224' | 'RIPEMD-160';

export type RSAKeyPairAlgorithm = 'RSASSA-PKCS1-v1_5' | 'RSA-PSS' | 'RSA-OAEP';

export interface RsaHashedKeyGenParams {
  name: RSAKeyPairAlgorithm;
  modulusLength: number;
  publicExponent: Uint8Array;
  hash: string | { name: string };
}

export interface RsaKeyAlgorithm {
  name: RSAKeyPairAlgorithm;
  modulusLength: number;
  publicExponent: Uint8Array;
  hash: { name: string };
}

export type ECKeyPairAlgorithm = 'ECDSA' | 'ECDH';

export type CFRGKeyPairAlgorithm = 'Ed25519' | 'Ed448' | 'X25519' | 'X448';
export type CFRGKeyPairType = 'ed25519' | 'ed448' | 'x25519' | 'x448';

export type PQCKeyPairAlgorithm =
  | 'ML-DSA-44'
  | 'ML-DSA-65'
  | 'ML-DSA-87'
  | 'ML-KEM-512'
  | 'ML-KEM-768'
  | 'ML-KEM-1024';
export type PQCKeyPairType =
  | 'ml-dsa-44'
  | 'ml-dsa-65'
  | 'ml-dsa-87'
  | 'ml-kem-512'
  | 'ml-kem-768'
  | 'ml-kem-1024';

export type MlKemAlgorithm = 'ML-KEM-512' | 'ML-KEM-768' | 'ML-KEM-1024';

export interface EncapsulateResult {
  sharedKey: ArrayBuffer;
  ciphertext: ArrayBuffer;
}

// Node.js style key pair types (lowercase)
export type RSAKeyPairType = 'rsa' | 'rsa-pss';
export type ECKeyPairType = 'ec';
export type DSAKeyPairType = 'dsa';
export type DHKeyPairType = 'dh';

export type KeyPairAlgorithm =
  | RSAKeyPairAlgorithm
  | ECKeyPairAlgorithm
  | CFRGKeyPairAlgorithm
  | PQCKeyPairAlgorithm;

export type AESAlgorithm =
  | 'AES-CTR'
  | 'AES-CBC'
  | 'AES-GCM'
  | 'AES-KW'
  | 'AES-OCB';

export type SecretKeyAlgorithm = 'HMAC' | AESAlgorithm;

export type SignVerifyAlgorithm =
  | 'RSASSA-PKCS1-v1_5'
  | 'RSA-PSS'
  | 'ECDSA'
  | 'HMAC'
  | 'Ed25519'
  | 'Ed448'
  | 'ML-DSA-44'
  | 'ML-DSA-65'
  | 'ML-DSA-87';

export type Argon2Algorithm = 'Argon2d' | 'Argon2i' | 'Argon2id';

export type DeriveBitsAlgorithm =
  | 'PBKDF2'
  | 'HKDF'
  | 'ECDH'
  | 'X25519'
  | 'X448'
  | Argon2Algorithm;

export type EncryptDecryptAlgorithm =
  | 'RSA-OAEP'
  | 'AES-CTR'
  | 'AES-CBC'
  | 'AES-GCM'
  | 'AES-KW'
  | 'AES-OCB'
  | 'ChaCha20-Poly1305';

export type RsaOaepParams = {
  name: 'RSA-OAEP';
  label?: BufferLike;
};

export type AesCbcParams = {
  name: 'AES-CBC';
  iv: BufferLike;
};

export type AesCtrParams = {
  name: 'AES-CTR';
  counter: TypedArray;
  length: number;
};

export type AesGcmParams = {
  name: 'AES-GCM';
  iv: BufferLike;
  tagLength?: TagLength;
  additionalData?: BufferLike;
};

export type ChaCha20Poly1305Params = {
  name: 'ChaCha20-Poly1305';
  iv: BufferLike;
  tagLength?: 128;
  additionalData?: BufferLike;
};

export type AesOcbParams = {
  name: 'AES-OCB';
  iv: BufferLike;
  tagLength?: 64 | 96 | 128;
  additionalData?: BufferLike;
};

export type AesKwParams = {
  name: 'AES-KW';
  wrappingKey?: BufferLike;
};

export type AesKeyGenParams = {
  length: AESLength;
  name?: AESAlgorithm;
};

export type TagLength = 32 | 64 | 96 | 104 | 112 | 120 | 128;

export type AESLength = 128 | 192 | 256;

export type EncryptDecryptParams =
  | AesCbcParams
  | AesCtrParams
  | AesGcmParams
  | AesOcbParams
  | AesKwParams
  | RsaOaepParams
  | ChaCha20Poly1305Params;

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
  salt?: string | BufferLike;
  iterations?: number;
  hash?: HashAlgorithm | string | { name: string };
  namedCurve?: NamedCurve;
  length?: number;
  modulusLength?: number;
  publicExponent?: number | Uint8Array;
  saltLength?: number;
  public?: CryptoKey;
  info?: BufferLike;
  // Argon2 parameters
  nonce?: BufferLike;
  parallelism?: number;
  tagLength?: number;
  memory?: number;
  passes?: number;
  secretValue?: BufferLike;
  associatedData?: BufferLike;
  version?: number;
};

export type KeyPairType =
  | CFRGKeyPairType
  | RSAKeyPairType
  | ECKeyPairType
  | DSAKeyPairType
  | DHKeyPairType;

export type KeyUsage =
  | 'encrypt'
  | 'decrypt'
  | 'sign'
  | 'verify'
  | 'deriveKey'
  | 'deriveBits'
  | 'encapsulateBits'
  | 'decapsulateBits'
  | 'encapsulateKey'
  | 'decapsulateKey'
  | 'wrapKey'
  | 'unwrapKey';

// TODO: These enums need to be defined on the native side
export enum KFormatType {
  DER,
  PEM,
  JWK,
}

export enum KeyType {
  SECRET,
  PUBLIC,
  PRIVATE,
}

export enum KeyEncoding {
  PKCS1,
  PKCS8,
  SPKI,
  SEC1,
}

export enum KeyFormat {
  RAW,
  PKCS8,
  SPKI,
  JWK,
}

export type KeyData = BufferLike | BinaryLike | JWK;

export const kNamedCurveAliases = {
  'P-256': 'prime256v1',
  'P-384': 'secp384r1',
  'P-521': 'secp521r1',
} as const;
// end TODO

export type KeyPairGenConfig = {
  publicFormat?: KFormatType | -1;
  publicType?: KeyEncoding;
  privateFormat?: KFormatType | -1;
  privateType?: KeyEncoding;
  cipher?: string;
  passphrase?: ArrayBuffer;
};

export type AsymmetricKeyType =
  | 'rsa'
  | 'rsa-pss'
  | 'dsa'
  | 'ec'
  | 'dh'
  | CFRGKeyPairType
  | PQCKeyPairType;

type JWKkty = 'AES' | 'RSA' | 'EC' | 'oct' | 'OKP';
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

export type KeyPairKey =
  | ArrayBuffer
  | Buffer
  | string
  | KeyObject
  | KeyObjectHandle
  | CryptoKey
  | undefined;

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

export type WebCryptoKeyPair = {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
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

// These are for shortcomings in @types/node
// Here we use "*Type" instead of "*Types" like node does.
// export type CipherCBCType = 'aes-128-cbc' | 'aes-192-cbc' | 'aes-256-cbc';
export type CipherCFBType =
  | 'aes-128-cfb'
  | 'aes-192-cfb'
  | 'aes-256-cfb'
  | 'aes-128-cfb1'
  | 'aes-192-cfb1'
  | 'aes-256-cfb1'
  | 'aes-128-cfb8'
  | 'aes-192-cfb8'
  | 'aes-256-cfb8';
export type CipherCTRType = 'aes-128-ctr' | 'aes-192-ctr' | 'aes-256-ctr';
export type CipherDESType =
  | 'des'
  | 'des3'
  | 'des-cbc'
  | 'des-ecb'
  | 'des-ede'
  | 'des-ede-cbc'
  | 'des-ede3'
  | 'des-ede3-cbc';
export type CipherECBType = 'aes-128-ecb' | 'aes-192-ecb' | 'aes-256-ecb';
export type CipherGCMType = 'aes-128-gcm' | 'aes-192-gcm' | 'aes-256-gcm';
export type CipherOFBType = 'aes-128-ofb' | 'aes-192-ofb' | 'aes-256-ofb';

export type KeyObjectHandle = KeyObjectHandleType;

export type DiffieHellmanOptions = {
  privateKey: KeyObject;
  publicKey: KeyObject;
};

export type DiffieHellmanCallback = (
  err: Error | null,
  secret?: CraftzdogBuffer,
) => CraftzdogBuffer | void;

// from @paulmillr/noble-curves
export type Hex = string | Uint8Array;

export type ImportFormat =
  | 'raw'
  | 'raw-public'
  | 'raw-secret'
  | 'raw-seed'
  | 'pkcs8'
  | 'spki'
  | 'jwk';

export type Operation =
  | 'encrypt'
  | 'decrypt'
  | 'sign'
  | 'verify'
  | 'generateKey'
  | 'importKey'
  | 'exportKey'
  | 'deriveBits'
  | 'wrapKey'
  | 'unwrapKey'
  | 'encapsulateBits'
  | 'decapsulateBits'
  | 'encapsulateKey'
  | 'decapsulateKey';

export interface KeyPairOptions {
  namedCurve: string;
  publicKeyEncoding?: {
    type: 'spki';
    format: 'pem' | 'der';
  };
  privateKeyEncoding?: {
    type: 'pkcs8';
    format: 'pem' | 'der';
    cipher?: string;
    passphrase?: string;
  };
}
