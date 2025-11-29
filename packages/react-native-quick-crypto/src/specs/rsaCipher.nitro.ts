import type { HybridObject } from 'react-native-nitro-modules';
import type { KeyObjectHandle } from './keyObjectHandle.nitro';

export interface RsaCipher
  extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  /**
   * Encrypt data using RSA-OAEP
   * @param keyHandle The public key handle
   * @param data The data to encrypt
   * @param hashAlgorithm The hash algorithm (e.g., 'SHA-256')
   * @param label Optional label for OAEP
   * @returns Encrypted data
   */
  encrypt(
    keyHandle: KeyObjectHandle,
    data: ArrayBuffer,
    hashAlgorithm: string,
    label?: ArrayBuffer,
  ): ArrayBuffer;

  /**
   * Decrypt data using RSA-OAEP
   * @param keyHandle The private key handle
   * @param data The data to decrypt
   * @param hashAlgorithm The hash algorithm (e.g., 'SHA-256')
   * @param label Optional label for OAEP
   * @returns Decrypted data
   */
  decrypt(
    keyHandle: KeyObjectHandle,
    data: ArrayBuffer,
    hashAlgorithm: string,
    label?: ArrayBuffer,
  ): ArrayBuffer;
}
