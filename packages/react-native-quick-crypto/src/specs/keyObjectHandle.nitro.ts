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
  exportRawPublic(): ArrayBuffer;
  exportRawPrivate(): ArrayBuffer;
  exportRawSeed(): ArrayBuffer;
  exportECPublicRaw(compressed: boolean): ArrayBuffer;
  exportECPrivateRaw(): ArrayBuffer;
  getAsymmetricKeyType(): AsymmetricKeyType;
  init(
    keyType: KeyType,
    key: string | ArrayBuffer,
    format?: KFormatType,
    type?: KeyEncoding,
    passphrase?: ArrayBuffer,
  ): boolean;
  initECRaw(namedCurve: string, keyData: ArrayBuffer): boolean;
  initPqcRaw(
    algorithmName: string,
    keyData: ArrayBuffer,
    isPublic: boolean,
  ): boolean;
  initRawPublic(
    asymmetricKeyType: string,
    keyData: ArrayBuffer,
    namedCurve?: string,
  ): boolean;
  initRawPrivate(
    asymmetricKeyType: string,
    keyData: ArrayBuffer,
    namedCurve?: string,
  ): boolean;
  initRawSeed(asymmetricKeyType: string, keyData: ArrayBuffer): boolean;
  initJwk(keyData: JWK, namedCurve?: NamedCurve): KeyType | undefined;
  keyDetail(): KeyDetail;
  keyEquals(other: KeyObjectHandle): boolean;
  getSymmetricKeySize(): number;
  checkEcKeyData(): boolean;
}
