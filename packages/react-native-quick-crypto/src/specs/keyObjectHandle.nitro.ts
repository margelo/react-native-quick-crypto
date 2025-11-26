import { type HybridObject } from 'react-native-nitro-modules';
import type {
  AsymmetricKeyType,
  JWK,
  KeyDetail,
  KeyEncoding,
  KeyType,
  KFormatType,
  NamedCurve,
} from '../utils';

export interface KeyObjectHandle
  extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  exportKey(
    format?: KFormatType,
    type?: KeyEncoding,
    cipher?: string,
    passphrase?: ArrayBuffer,
  ): ArrayBuffer;
  exportJwk(key: JWK, handleRsaPss: boolean): JWK;
  getAsymmetricKeyType(): AsymmetricKeyType;
  init(
    keyType: KeyType,
    key: string | ArrayBuffer,
    format?: KFormatType,
    type?: KeyEncoding,
    passphrase?: ArrayBuffer,
  ): boolean;
  initECRaw(namedCurve: string, keyData: ArrayBuffer): boolean;
  initJwk(keyData: JWK, namedCurve?: NamedCurve): KeyType | undefined;
  keyDetail(): KeyDetail;
}
