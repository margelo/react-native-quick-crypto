import type {
  AnyAlgorithm,
  DeriveBitsAlgorithm,
  DigestAlgorithm,
  EncryptDecryptAlgorithm,
  EncryptDecryptParams,
  KeyPairAlgorithm,
  SecretKeyAlgorithm,
  SignVerifyAlgorithm,
  SubtleAlgorithm,
} from './keys';

type SupportedAlgorithm<Type extends string> = {
  [key in Type]: string | null;
};

type SupportedAlgorithms = {
  digest: SupportedAlgorithm<DigestAlgorithm>;
  generateKey: SupportedAlgorithm<KeyPairAlgorithm | SecretKeyAlgorithm>;
  sign: SupportedAlgorithm<SignVerifyAlgorithm>;
  verify: SupportedAlgorithm<SignVerifyAlgorithm>;
  importKey: SupportedAlgorithm<
    KeyPairAlgorithm | 'PBKDF2' | SecretKeyAlgorithm | 'HKDF'
  >;
  deriveBits: SupportedAlgorithm<DeriveBitsAlgorithm>;
  encrypt: SupportedAlgorithm<EncryptDecryptAlgorithm>;
  decrypt: SupportedAlgorithm<EncryptDecryptAlgorithm>;
  'get key length': SupportedAlgorithm<SecretKeyAlgorithm | 'PBKDF2' | 'HKDF'>;
  wrapKey: SupportedAlgorithm<'AES-KW'>;
  unwrapKey: SupportedAlgorithm<'AES-KW'>;
};

export type Operation =
  | 'digest'
  | 'generateKey'
  | 'sign'
  | 'verify'
  | 'importKey'
  | 'deriveBits'
  | 'encrypt'
  | 'decrypt'
  | 'get key length'
  | 'wrapKey'
  | 'unwrapKey';

const kSupportedAlgorithms: SupportedAlgorithms = {
  digest: {
    'SHA-1': null,
    'SHA-256': null,
    'SHA-384': null,
    'SHA-512': null,
  },
  generateKey: {
    'RSASSA-PKCS1-v1_5': 'RsaHashedKeyGenParams',
    'RSA-PSS': 'RsaHashedKeyGenParams',
    'RSA-OAEP': 'RsaHashedKeyGenParams',
    ECDSA: 'EcKeyGenParams',
    ECDH: 'EcKeyGenParams',
    'AES-CTR': 'AesKeyGenParams',
    'AES-CBC': 'AesKeyGenParams',
    'AES-GCM': 'AesKeyGenParams',
    'AES-KW': 'AesKeyGenParams',
    HMAC: 'HmacKeyGenParams',
    X25519: null,
    Ed25519: null,
    X448: null,
    Ed448: null,
  },
  sign: {
    'RSASSA-PKCS1-v1_5': null,
    'RSA-PSS': 'RsaPssParams',
    ECDSA: 'EcdsaParams',
    HMAC: null,
    Ed25519: null,
    Ed448: 'Ed448Params',
  },
  verify: {
    'RSASSA-PKCS1-v1_5': null,
    'RSA-PSS': 'RsaPssParams',
    ECDSA: 'EcdsaParams',
    HMAC: null,
    Ed25519: null,
    Ed448: 'Ed448Params',
  },
  importKey: {
    'RSASSA-PKCS1-v1_5': 'RsaHashedImportParams',
    'RSA-PSS': 'RsaHashedImportParams',
    'RSA-OAEP': 'RsaHashedImportParams',
    ECDSA: 'EcKeyImportParams',
    ECDH: 'EcKeyImportParams',
    HMAC: 'HmacImportParams',
    HKDF: null,
    PBKDF2: null,
    'AES-CTR': null,
    'AES-CBC': null,
    'AES-GCM': null,
    'AES-KW': null,
    Ed25519: null,
    X25519: null,
    Ed448: null,
    X448: null,
  },
  deriveBits: {
    HKDF: 'HkdfParams',
    PBKDF2: 'Pbkdf2Params',
    ECDH: 'EcdhKeyDeriveParams',
    X25519: 'EcdhKeyDeriveParams',
    X448: 'EcdhKeyDeriveParams',
  },
  encrypt: {
    'RSA-OAEP': 'RsaOaepParams',
    'AES-CBC': 'AesCbcParams',
    'AES-GCM': 'AesGcmParams',
    'AES-CTR': 'AesCtrParams',
  },
  decrypt: {
    'RSA-OAEP': 'RsaOaepParams',
    'AES-CBC': 'AesCbcParams',
    'AES-GCM': 'AesGcmParams',
    'AES-CTR': 'AesCtrParams',
  },
  'get key length': {
    'AES-CBC': 'AesDerivedKeyParams',
    'AES-CTR': 'AesDerivedKeyParams',
    'AES-GCM': 'AesDerivedKeyParams',
    'AES-KW': 'AesDerivedKeyParams',
    HMAC: 'HmacImportParams',
    HKDF: null,
    PBKDF2: null,
  },
  wrapKey: {
    'AES-KW': null,
  },
  unwrapKey: {
    'AES-KW': null,
  },
};

type AlgorithmDictionaries = {
  [key in string]: object;
};

const simpleAlgorithmDictionaries: AlgorithmDictionaries = {
  AesGcmParams: { iv: 'BufferSource', additionalData: 'BufferSource' },
  RsaHashedKeyGenParams: { hash: 'HashAlgorithmIdentifier' },
  EcKeyGenParams: {},
  HmacKeyGenParams: { hash: 'HashAlgorithmIdentifier' },
  RsaPssParams: {},
  EcdsaParams: { hash: 'HashAlgorithmIdentifier' },
  HmacImportParams: { hash: 'HashAlgorithmIdentifier' },
  HkdfParams: {
    hash: 'HashAlgorithmIdentifier',
    salt: 'BufferSource',
    info: 'BufferSource',
  },
  Ed448Params: { context: 'BufferSource' },
  Pbkdf2Params: { hash: 'HashAlgorithmIdentifier', salt: 'BufferSource' },
  RsaOaepParams: { label: 'BufferSource' },
  RsaHashedImportParams: { hash: 'HashAlgorithmIdentifier' },
  EcKeyImportParams: {},
};

// https://w3c.github.io/webcrypto/#algorithm-normalization-normalize-an-algorithm
// adapted for Node.js from Deno's implementation
// https://github.com/denoland/deno/blob/v1.29.1/ext/crypto/00_crypto.js#L195
export const normalizeAlgorithm = (
  algorithm: SubtleAlgorithm | EncryptDecryptParams | AnyAlgorithm,
  op: Operation,
): SubtleAlgorithm | EncryptDecryptParams => {
  if (typeof algorithm === 'string') {
    return normalizeAlgorithm({ name: algorithm }, op);
  }

  // 1.
  const registeredAlgorithms = kSupportedAlgorithms[op];
  // 2. 3.
  // commented, because typescript takes care of this for us 🤞👀
  // const initialAlg = webidl.converters.Algorithm(algorithm, {
  //   prefix: 'Failed to normalize algorithm',
  //   context: 'passed algorithm',
  // });

  // 4.
  let algName = algorithm.name;
  if (algName === undefined) return { name: 'unknown' };

  // 5.
  let desiredType: string | null | undefined;
  for (const key in registeredAlgorithms) {
    if (!Object.prototype.hasOwnProperty.call(registeredAlgorithms, key)) {
      continue;
    }
    if (key.toUpperCase() === algName.toUpperCase()) {
      algName = key as AnyAlgorithm;
      desiredType = (
        registeredAlgorithms as Record<string, typeof desiredType>
      )[algName];
    }
  }
  if (desiredType === undefined)
    throw new Error(`Unrecognized algorithm name: ${algName}`);

  // Fast path everything below if the registered dictionary is null
  if (desiredType === null) return { name: algName };

  // 6.
  const normalizedAlgorithm = algorithm;
  // TODO: implement this?  Maybe via typescript?
  // webidl.converters[desiredType](algorithm, {
  //   prefix: 'Failed to normalize algorithm',
  //   context: 'passed algorithm',
  // });
  // 7.
  normalizedAlgorithm.name = algName;

  // 9.
  const dict = simpleAlgorithmDictionaries[desiredType];
  // 10.
  const dictKeys = dict ? Object.keys(dict) : [];
  for (let i = 0; i < dictKeys.length; i++) {
    const member = dictKeys[i] || '';
    if (!Object.prototype.hasOwnProperty.call(dict, member)) continue;
    // TODO: implement this?  Maybe via typescript?
    // const idlType = dict[member];
    // const idlValue = normalizedAlgorithm[member];
    // 3.
    // if (idlType === 'BufferSource' && idlValue) {
    //   const isView = ArrayBufferIsView(idlValue);
    //   normalizedAlgorithm[member] = TypedArrayPrototypeSlice(
    //     new Uint8Array(
    //       isView ? getDataViewOrTypedArrayBuffer(idlValue) : idlValue,
    //       isView ? getDataViewOrTypedArrayByteOffset(idlValue) : 0,
    //       isView
    //         ? getDataViewOrTypedArrayByteLength(idlValue)
    //         : ArrayBufferPrototypeGetByteLength(idlValue)
    //     )
    //   );
    // } else if (idlType === 'HashAlgorithmIdentifier') {
    //   normalizedAlgorithm[member] = normalizeAlgorithm(idlValue, 'digest');
    // } else if (idlType === 'AlgorithmIdentifier') {
    //   // This extension point is not used by any supported algorithm (yet?)
    //   throw lazyDOMException('Not implemented.', 'NotSupportedError');
    // }
  }

  return normalizedAlgorithm;
};
