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

  async sign(message: ArrayBuffer): Promise<ArrayBuffer> {
    return this.native.sign(message);
  }

  signSync(message: ArrayBuffer): ArrayBuffer {
    return this.native.signSync(message);
  }

  async verify(signature: ArrayBuffer, message: ArrayBuffer): Promise<boolean> {
    return this.native.verify(signature, message);
  }

  verifySync(signature: ArrayBuffer, message: ArrayBuffer): boolean {
    return this.native.verifySync(signature, message);
  }
}
