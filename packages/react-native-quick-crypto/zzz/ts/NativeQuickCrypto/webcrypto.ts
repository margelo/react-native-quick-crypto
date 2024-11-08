import type { AESCipher } from './aes';
import type {
  AsymmetricKeyType,
  JWK,
  KeyEncoding,
  KeyType,
  KFormatType,
  KWebCryptoKeyFormat,
  NamedCurve,
} from '../keys';
import type { SignVerify } from './sig';
import type {
  GenerateSecretKeyMethod,
  GenerateSecretKeySyncMethod,
} from './keygen';
import type { KeyVariant } from './Cipher';
import type { RSACipher } from './rsa';


type ECExportKey = (
  format: KWebCryptoKeyFormat,
  handle: KeyObjectHandle
) => ArrayBuffer;

type RSAExportKey = (
  format: KWebCryptoKeyFormat,
  handle: KeyObjectHandle,
  variant: KeyVariant
) => ArrayBuffer;



type CreateKeyObjectHandle = () => KeyObjectHandle;

export type webcrypto = {
  aesCipher: AESCipher;
  createKeyObjectHandle: CreateKeyObjectHandle;
  ecExportKey: ECExportKey;
  generateSecretKey: GenerateSecretKeyMethod;
  generateSecretKeySync: GenerateSecretKeySyncMethod;
  rsaCipher: RSACipher;
  rsaExportKey: RSAExportKey;
  signVerify: SignVerify;
};
