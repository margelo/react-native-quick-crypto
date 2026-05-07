import {
  binaryLikeToArrayBuffer,
  isStringOrBuffer,
  KeyEncoding,
  KFormatType,
} from '../utils';
import type { CryptoKeyPair, EncodingOptions } from '../utils';
import type { CryptoKey, PublicKeyObject, PrivateKeyObject } from './classes';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const isCryptoKey = (obj: any): boolean => {
  return obj !== null && obj?.keyObject !== undefined;
};

export function exportPublicKeyRaw(
  pub: PublicKeyObject,
  pointType: 'compressed' | 'uncompressed' | undefined,
): ArrayBuffer {
  if (pub.asymmetricKeyType === 'ec') {
    return pub.handle.exportECPublicRaw(pointType === 'compressed');
  }
  return pub.handle.exportRawPublic();
}

export function exportPrivateKeyRaw(
  priv: PrivateKeyObject,
  format: 'raw-private' | 'raw-seed',
): ArrayBuffer {
  if (format === 'raw-seed') {
    return priv.handle.exportRawSeed();
  }
  if (priv.asymmetricKeyType === 'ec') {
    return priv.handle.exportECPrivateRaw();
  }
  return priv.handle.exportRawPrivate();
}

export function getCryptoKeyPair(
  key: CryptoKey | CryptoKeyPair,
): CryptoKeyPair {
  if ('publicKey' in key && 'privateKey' in key) return key;
  throw new Error('Invalid CryptoKeyPair');
}

/**
 * Parses the public key encoding based on an object. keyType must be undefined
 * when this is used to parse an input encoding and must be a valid key type if
 * used to parse an output encoding.
 */
export function parsePublicKeyEncoding(
  enc: EncodingOptions,
  keyType: string | undefined,
  objName?: string,
) {
  return parseKeyEncoding(enc, keyType, keyType ? true : undefined, objName);
}

/**
 * Parses the private key encoding based on an object. keyType must be undefined
 * when this is used to parse an input encoding and must be a valid key type if
 * used to parse an output encoding.
 */
export function parsePrivateKeyEncoding(
  enc: EncodingOptions,
  keyType: string | undefined,
  objName?: string,
) {
  return parseKeyEncoding(enc, keyType, false, objName);
}

export function parseKeyEncoding(
  enc: EncodingOptions,
  keyType?: string,
  isPublic?: boolean,
  objName?: string,
) {
  // validateObject(enc, 'options');

  const isInput = keyType === undefined;

  const { format, type } = parseKeyFormatAndType(
    enc,
    keyType,
    isPublic,
    objName,
  );

  if (
    format === 'raw-public' ||
    format === 'raw-private' ||
    format === 'raw-seed'
  ) {
    if (enc.cipher != null || enc.passphrase !== undefined) {
      throw new Error(
        `Incompatible key options: ${format} does not support encryption`,
      );
    }
    return { format, type, cipher: undefined, passphrase: undefined };
  }

  let cipher, passphrase, encoding;
  if (isPublic !== true) {
    ({ cipher, passphrase, encoding } = enc);

    if (!isInput) {
      if (cipher != null) {
        if (typeof cipher !== 'string')
          throw new Error(
            `Invalid argument ${option('cipher', objName)}: ${cipher}`,
          );
        if (
          format === KFormatType.DER &&
          (type === KeyEncoding.PKCS1 || type === KeyEncoding.SEC1)
        ) {
          throw new Error(
            `Incompatible key options ${encodingNames[type as KeyEncoding]} does not support encryption`,
          );
        }
      } else if (passphrase !== undefined) {
        throw new Error(
          `invalid argument ${option('cipher', objName)}: ${cipher}`,
        );
      }
    }

    if (
      (isInput && passphrase !== undefined && !isStringOrBuffer(passphrase)) ||
      (!isInput && cipher != null && !isStringOrBuffer(passphrase))
    ) {
      throw new Error(
        `Invalid argument value ${option('passphrase', objName)}: ${passphrase}`,
      );
    }
  }

  if (passphrase !== undefined)
    passphrase = binaryLikeToArrayBuffer(passphrase, encoding);

  return { format, type, cipher, passphrase };
}

const encodingNames = {
  [KeyEncoding.PKCS1]: 'pkcs1',
  [KeyEncoding.PKCS8]: 'pkcs8',
  [KeyEncoding.SPKI]: 'spki',
  [KeyEncoding.SEC1]: 'sec1',
};

function option(name: string, objName?: string) {
  return objName === undefined
    ? `options.${name}`
    : `options.${objName}.${name}`;
}

function parseKeyFormat(
  formatStr?: string,
  defaultFormat?: KFormatType,
  optionName?: string,
): KFormatType | 'raw-public' | 'raw-private' | 'raw-seed' {
  if (formatStr === undefined && defaultFormat !== undefined)
    return defaultFormat;
  else if (formatStr === 'pem') return KFormatType.PEM;
  else if (formatStr === 'der') return KFormatType.DER;
  else if (formatStr === 'jwk') return KFormatType.JWK;
  else if (formatStr === 'raw-public') return 'raw-public';
  else if (formatStr === 'raw-private') return 'raw-private';
  else if (formatStr === 'raw-seed') return 'raw-seed';
  throw new Error(`Invalid key format str: ${optionName}`);
}

function parseKeyType(
  typeStr: string | undefined,
  required: boolean,
  keyType: string | undefined,
  isPublic: boolean | undefined,
  optionName: string,
): KeyEncoding | undefined {
  if (typeStr === undefined && !required) {
    return undefined;
  } else if (typeStr === 'pkcs1') {
    if (keyType !== undefined && keyType !== 'rsa') {
      throw new Error(
        `Crypto incompatible key options: ${typeStr} can only be used for RSA keys`,
      );
    }
    return KeyEncoding.PKCS1;
  } else if (typeStr === 'spki' && isPublic !== false) {
    return KeyEncoding.SPKI;
  } else if (typeStr === 'pkcs8' && isPublic !== true) {
    return KeyEncoding.PKCS8;
  } else if (typeStr === 'sec1' && isPublic !== true) {
    if (keyType !== undefined && keyType !== 'ec') {
      throw new Error(
        `Incompatible key options ${typeStr} can only be used for EC keys`,
      );
    }
    return KeyEncoding.SEC1;
  }

  throw new Error(`Invalid option ${optionName} - ${typeStr}`);
}

function parseKeyFormatAndType(
  enc: EncodingOptions,
  keyType?: string,
  isPublic?: boolean,
  objName?: string,
): {
  format: KFormatType | 'raw-public' | 'raw-private' | 'raw-seed';
  type: KeyEncoding | 'compressed' | 'uncompressed' | undefined;
} {
  const { format: formatStr, type: typeStr } = enc;

  const isInput = keyType === undefined;
  const format = parseKeyFormat(
    formatStr,
    isInput ? KFormatType.PEM : undefined,
    option('format', objName),
  );

  if (format === 'raw-public') {
    if (isPublic === false) {
      throw new Error(
        `Invalid format 'raw-public' for ${option('format', objName)}`,
      );
    }
    if (typeStr === undefined || typeStr === 'uncompressed') {
      return { format, type: 'uncompressed' };
    }
    if (typeStr === 'compressed') {
      return { format, type: 'compressed' };
    }
    throw new Error(
      `Invalid ${option('type', objName)} for raw-public: ${typeStr}`,
    );
  }

  if (format === 'raw-private' || format === 'raw-seed') {
    if (isPublic === true) {
      throw new Error(
        `Invalid format '${format}' for ${option('format', objName)}`,
      );
    }
    if (typeStr !== undefined) {
      throw new Error(
        `Invalid ${option('type', objName)} for ${format}: ${typeStr}`,
      );
    }
    return { format, type: undefined };
  }

  const isRequired =
    (!isInput || format === KFormatType.DER) && format !== KFormatType.JWK;

  const type = parseKeyType(
    typeStr as string | undefined,
    isRequired,
    keyType,
    isPublic,
    option('type', objName),
  );
  return { format, type };
}
