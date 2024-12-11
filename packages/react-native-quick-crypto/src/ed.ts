import { NitroModules } from 'react-native-nitro-modules';
import type { EdKeyPair } from './specs/edKeyPair.nitro';
import type { CFRGKeyPairType, KeyPairGenConfig } from './utils';

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

  async sign(message: ArrayBuffer, key?: ArrayBuffer): Promise<ArrayBuffer> {
    return key ? this.native.sign(message, key) : this.native.sign(message);
  }

  signSync(message: ArrayBuffer, key?: ArrayBuffer): ArrayBuffer {
    return key
      ? this.native.signSync(message, key)
      : this.native.signSync(message);
  }

  async verify(
    message: ArrayBuffer,
    signature: ArrayBuffer,
    key?: ArrayBuffer,
  ): Promise<boolean> {
    return key
      ? this.native.verify(message, signature, key)
      : this.native.verify(message, signature);
  }

  verifySync(
    message: ArrayBuffer,
    signature: ArrayBuffer,
    key?: ArrayBuffer,
  ): boolean {
    return key
      ? this.native.verifySync(message, signature, key)
      : this.native.verifySync(message, signature);
  }
}
