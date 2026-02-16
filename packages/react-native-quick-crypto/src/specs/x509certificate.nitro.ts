import type { HybridObject } from 'react-native-nitro-modules';
import type { KeyObjectHandle } from './keyObjectHandle.nitro';

export interface X509CertificateHandle
  extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  init(buffer: ArrayBuffer): void;

  subject(): string;
  subjectAltName(): string;
  issuer(): string;
  infoAccess(): string;
  validFrom(): string;
  validTo(): string;
  validFromDate(): number;
  validToDate(): number;
  signatureAlgorithm(): string;
  signatureAlgorithmOid(): string;
  serialNumber(): string;

  fingerprint(): string;
  fingerprint256(): string;
  fingerprint512(): string;

  raw(): ArrayBuffer;
  pem(): string;

  publicKey(): KeyObjectHandle;
  keyUsage(): string[];

  ca(): boolean;
  checkIssued(other: X509CertificateHandle): boolean;
  checkPrivateKey(key: KeyObjectHandle): boolean;
  verify(key: KeyObjectHandle): boolean;

  checkHost(name: string, flags: number): string | undefined;
  checkEmail(email: string, flags: number): string | undefined;
  checkIP(ip: string): string | undefined;
}
