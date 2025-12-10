import type { HybridObject } from 'react-native-nitro-modules';
import type { KeyObjectHandle } from './keyObjectHandle.nitro';

export interface RsaCipher
  extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  /**
   * Encrypt data using RSA with specified padding
   * @param keyHandle The public key handle
   * @param data The data to encrypt
   * @param padding RSA padding mode (1=PKCS1, 4=OAEP)
   * @param hashAlgorithm The hash algorithm for OAEP (e.g., 'SHA-256')
   * @param label Optional label for OAEP
   * @returns Encrypted data
   */
  encrypt(
    keyHandle: KeyObjectHandle,
    data: ArrayBuffer,
    padding: number,
    hashAlgorithm: string,
    label?: ArrayBuffer,
  ): ArrayBuffer;

  /**
   * Decrypt data using RSA with specified padding
   * @param keyHandle The private key handle
   * @param data The data to decrypt
   * @param padding RSA padding mode (1=PKCS1, 4=OAEP)
   * @param hashAlgorithm The hash algorithm for OAEP (e.g., 'SHA-256')
   * @param label Optional label for OAEP
   * @returns Decrypted data
   */
  decrypt(
    keyHandle: KeyObjectHandle,
    data: ArrayBuffer,
    padding: number,
    hashAlgorithm: string,
    label?: ArrayBuffer,
  ): ArrayBuffer;

  /**
   * Decrypt data using public key (inverse of privateEncrypt, for signature verification)
   * @param keyHandle The public key handle
   * @param data The data to decrypt
   * @param padding RSA padding mode (1=PKCS1)
   * @returns Decrypted data
   */
  publicDecrypt(
    keyHandle: KeyObjectHandle,
    data: ArrayBuffer,
    padding: number,
  ): ArrayBuffer;

  /**
   * Encrypt data using private key (for signatures)
   * @param keyHandle The private key handle
   * @param data The data to encrypt
   * @param padding RSA padding mode (1=PKCS1)
   * @returns Encrypted data
   */
  privateEncrypt(
    keyHandle: KeyObjectHandle,
    data: ArrayBuffer,
    padding: number,
  ): ArrayBuffer;

  /**
   * Decrypt data using private key (inverse of publicEncrypt)
   * @param keyHandle The private key handle
   * @param data The data to decrypt
   * @param padding RSA padding mode (1=PKCS1, 4=OAEP)
   * @param hashAlgorithm The hash algorithm for OAEP (e.g., 'SHA-256')
   * @param label Optional label for OAEP
   * @returns Decrypted data
   */
  privateDecrypt(
    keyHandle: KeyObjectHandle,
    data: ArrayBuffer,
    padding: number,
    hashAlgorithm: string,
    label?: ArrayBuffer,
  ): ArrayBuffer;
}
