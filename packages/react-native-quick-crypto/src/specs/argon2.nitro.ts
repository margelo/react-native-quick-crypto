import type { HybridObject } from 'react-native-nitro-modules';

export interface Argon2 extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  hash(
    algorithm: string,
    message: ArrayBuffer,
    nonce: ArrayBuffer,
    parallelism: number,
    tagLength: number,
    memory: number,
    passes: number,
    version: number,
    secret?: ArrayBuffer,
    associatedData?: ArrayBuffer,
  ): Promise<ArrayBuffer>;

  hashSync(
    algorithm: string,
    message: ArrayBuffer,
    nonce: ArrayBuffer,
    parallelism: number,
    tagLength: number,
    memory: number,
    passes: number,
    version: number,
    secret?: ArrayBuffer,
    associatedData?: ArrayBuffer,
  ): ArrayBuffer;
}
