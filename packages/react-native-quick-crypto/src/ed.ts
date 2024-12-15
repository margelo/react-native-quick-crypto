import { NitroModules } from 'react-native-nitro-modules';
import { binaryLikeToArrayBuffer as toAB } from './utils';
import type { EdKeyPair } from './specs/edKeyPair.nitro';
import type { BinaryLike, CFRGKeyPairType, KeyPairGenConfig } from './utils';

export class Ed {
  type: CFRGKeyPairType;
  config: KeyPairGenConfig;
  native: EdKeyPair;

  constructor(type: CFRGKeyPairType, config: KeyPairGenConfig) {
    this.type = type;
    this.config = config;
    this.native = NitroModules.createHybridObject<EdKeyPair>('EdKeyPair');
    this.native.setCurve(type);
  }

  async generateKeyPair(): Promise<void> {
    this.native.generateKeyPair(
      this.config.publicFormat || (-1 as number),
      this.config.publicType || (-1 as number),
      this.config.privateFormat || (-1 as number),
      this.config.privateType || (-1 as number),
      this.config.cipher as string,
      this.config.passphrase as ArrayBuffer,
    );
  }

  generateKeyPairSync(): void {
    this.native.generateKeyPairSync(
      this.config.publicFormat || (-1 as number),
      this.config.publicType || (-1 as number),
      this.config.privateFormat || (-1 as number),
      this.config.privateType || (-1 as number),
      this.config.cipher as string,
      this.config.passphrase as ArrayBuffer,
    );
  }

  getPublicKey(): ArrayBuffer {
    return this.native.getPublicKey();
  }

  getPrivateKey(): ArrayBuffer {
    return this.native.getPrivateKey();
  }

  async sign(message: BinaryLike, key?: BinaryLike): Promise<ArrayBuffer> {
    return key
      ? this.native.sign(toAB(message), toAB(key))
      : this.native.sign(toAB(message));
  }

  signSync(message: BinaryLike, key?: BinaryLike): ArrayBuffer {
    return key
      ? this.native.signSync(toAB(message), toAB(key))
      : this.native.signSync(toAB(message));
  }

  async verify(
    signature: BinaryLike,
    message: BinaryLike,
    key?: BinaryLike,
  ): Promise<boolean> {
    return key
      ? this.native.verify(toAB(signature), toAB(message), toAB(key))
      : this.native.verify(toAB(signature), toAB(message));
  }

  verifySync(
    signature: BinaryLike,
    message: BinaryLike,
    key?: BinaryLike,
  ): boolean {
    return key
      ? this.native.verifySync(toAB(signature), toAB(message), toAB(key))
      : this.native.verifySync(toAB(signature), toAB(message));
  }
}
