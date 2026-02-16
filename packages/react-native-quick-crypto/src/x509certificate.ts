import { NitroModules } from 'react-native-nitro-modules';
import { Buffer } from '@craftzdog/react-native-buffer';
import type { X509CertificateHandle } from './specs/x509certificate.nitro';
import { PublicKeyObject, KeyObject } from './keys';
import type { BinaryLike } from './utils';
import { binaryLikeToArrayBuffer } from './utils';

const X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT = 0x1;
const X509_CHECK_FLAG_NO_WILDCARDS = 0x2;
const X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS = 0x4;
const X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS = 0x8;
const X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS = 0x10;
const X509_CHECK_FLAG_NEVER_CHECK_SUBJECT = 0x20;

export interface CheckOptions {
  subject?: 'default' | 'always' | 'never';
  wildcards?: boolean;
  partialWildcards?: boolean;
  multiLabelWildcards?: boolean;
  singleLabelSubdomains?: boolean;
}

function getFlags(options?: CheckOptions): number {
  if (!options) return 0;

  let flags = 0;

  if (options.subject === 'always') {
    flags |= X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT;
  } else if (options.subject === 'never') {
    flags |= X509_CHECK_FLAG_NEVER_CHECK_SUBJECT;
  }

  if (options.wildcards === false) {
    flags |= X509_CHECK_FLAG_NO_WILDCARDS;
  }

  if (options.partialWildcards === false) {
    flags |= X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS;
  }

  if (options.multiLabelWildcards === true) {
    flags |= X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS;
  }

  if (options.singleLabelSubdomains === true) {
    flags |= X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS;
  }

  return flags;
}

export class X509Certificate {
  private readonly handle: X509CertificateHandle;
  private readonly cache = new Map<string, unknown>();

  constructor(buffer: BinaryLike) {
    this.handle = NitroModules.createHybridObject<X509CertificateHandle>(
      'X509CertificateHandle',
    );

    let ab: ArrayBuffer;
    if (typeof buffer === 'string') {
      ab = Buffer.from(buffer).buffer as ArrayBuffer;
    } else {
      ab = binaryLikeToArrayBuffer(buffer);
    }

    this.handle.init(ab);
  }

  private cached<T>(key: string, compute: () => T): T {
    if (this.cache.has(key)) {
      return this.cache.get(key) as T;
    }
    const value = compute();
    this.cache.set(key, value);
    return value;
  }

  get subject(): string {
    return this.cached('subject', () => this.handle.subject());
  }

  get subjectAltName(): string {
    return this.cached('subjectAltName', () => this.handle.subjectAltName());
  }

  get issuer(): string {
    return this.cached('issuer', () => this.handle.issuer());
  }

  get infoAccess(): string {
    return this.cached('infoAccess', () => this.handle.infoAccess());
  }

  get validFrom(): string {
    return this.cached('validFrom', () => this.handle.validFrom());
  }

  get validTo(): string {
    return this.cached('validTo', () => this.handle.validTo());
  }

  get validFromDate(): Date {
    return this.cached(
      'validFromDate',
      () => new Date(this.handle.validFromDate()),
    );
  }

  get validToDate(): Date {
    return this.cached(
      'validToDate',
      () => new Date(this.handle.validToDate()),
    );
  }

  get fingerprint(): string {
    return this.cached('fingerprint', () => this.handle.fingerprint());
  }

  get fingerprint256(): string {
    return this.cached('fingerprint256', () => this.handle.fingerprint256());
  }

  get fingerprint512(): string {
    return this.cached('fingerprint512', () => this.handle.fingerprint512());
  }

  get keyUsage(): string[] {
    return this.cached('keyUsage', () => this.handle.keyUsage());
  }

  get extKeyUsage(): string[] {
    return this.keyUsage;
  }

  get serialNumber(): string {
    return this.cached('serialNumber', () => this.handle.serialNumber());
  }

  get signatureAlgorithm(): string {
    return this.cached('signatureAlgorithm', () =>
      this.handle.signatureAlgorithm(),
    );
  }

  get signatureAlgorithmOid(): string {
    return this.cached('signatureAlgorithmOid', () =>
      this.handle.signatureAlgorithmOid(),
    );
  }

  get ca(): boolean {
    return this.cached('ca', () => this.handle.ca());
  }

  get raw(): Buffer {
    return this.cached('raw', () => Buffer.from(this.handle.raw()));
  }

  get publicKey(): PublicKeyObject {
    return this.cached(
      'publicKey',
      () => new PublicKeyObject(this.handle.publicKey()),
    );
  }

  get issuerCertificate(): undefined {
    return undefined;
  }

  checkHost(name: string, options?: CheckOptions): string | undefined {
    if (typeof name !== 'string') {
      throw new TypeError('The "name" argument must be a string');
    }
    return this.handle.checkHost(name, getFlags(options));
  }

  checkEmail(email: string, options?: CheckOptions): string | undefined {
    if (typeof email !== 'string') {
      throw new TypeError('The "email" argument must be a string');
    }
    return this.handle.checkEmail(email, getFlags(options));
  }

  checkIP(ip: string): string | undefined {
    if (typeof ip !== 'string') {
      throw new TypeError('The "ip" argument must be a string');
    }
    return this.handle.checkIP(ip);
  }

  checkIssued(otherCert: X509Certificate): boolean {
    if (!(otherCert instanceof X509Certificate)) {
      throw new TypeError(
        'The "otherCert" argument must be an instance of X509Certificate',
      );
    }
    return this.handle.checkIssued(otherCert.handle);
  }

  checkPrivateKey(pkey: KeyObject): boolean {
    if (!(pkey instanceof KeyObject)) {
      throw new TypeError(
        'The "pkey" argument must be an instance of KeyObject',
      );
    }
    if (pkey.type !== 'private') {
      throw new TypeError('The "pkey" argument must be a private key');
    }
    return this.handle.checkPrivateKey(pkey.handle);
  }

  verify(pkey: KeyObject): boolean {
    if (!(pkey instanceof KeyObject)) {
      throw new TypeError(
        'The "pkey" argument must be an instance of KeyObject',
      );
    }
    if (pkey.type !== 'public') {
      throw new TypeError('The "pkey" argument must be a public key');
    }
    return this.handle.verify(pkey.handle);
  }

  toString(): string {
    return this.cached('pem', () => this.handle.pem());
  }

  toJSON(): string {
    return this.toString();
  }

  toLegacyObject(): Record<string, unknown> {
    return {
      subject: this.subject,
      issuer: this.issuer,
      subjectaltname: this.subjectAltName,
      infoAccess: this.infoAccess,
      ca: this.ca,
      modulus: undefined,
      bits: undefined,
      exponent: undefined,
      valid_from: this.validFrom,
      valid_to: this.validTo,
      fingerprint: this.fingerprint,
      fingerprint256: this.fingerprint256,
      fingerprint512: this.fingerprint512,
      ext_key_usage: this.keyUsage,
      serialNumber: this.serialNumber,
      raw: this.raw,
    };
  }
}
