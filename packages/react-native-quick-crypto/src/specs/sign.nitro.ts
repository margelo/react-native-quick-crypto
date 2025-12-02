import type { HybridObject } from 'react-native-nitro-modules';
import type { KeyObjectHandle } from './keyObjectHandle.nitro';

export interface SignHandle
  extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  init(algorithm: string): void;

  update(data: ArrayBuffer): void;

  sign(
    keyHandle: KeyObjectHandle,
    padding?: number,
    saltLength?: number,
    dsaEncoding?: number,
  ): ArrayBuffer;
}

export interface VerifyHandle
  extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  init(algorithm: string): void;

  update(data: ArrayBuffer): void;

  verify(
    keyHandle: KeyObjectHandle,
    signature: ArrayBuffer,
    padding?: number,
    saltLength?: number,
    dsaEncoding?: number,
  ): boolean;
}
