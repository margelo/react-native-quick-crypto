import { test } from '../util';
import { assert } from 'chai';
import {
  X509Certificate,
  createPrivateKey,
  generateKeyPairSync,
  Buffer,
} from 'react-native-quick-crypto';

const SUITE = 'x509';

const certPem = `-----BEGIN CERTIFICATE-----
MIIEgDCCA2igAwIBAgIUYX7QpAhywlWSvMIGfIhcXyF1S6kwDQYJKoZIhvcNAQEL
BQAwezELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM
DVNhbiBGcmFuY2lzY28xEjAQBgNVBAoMCVJOUUMgVGVzdDEQMA4GA1UECwwHVGVz
dGluZzEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTAgFw0yNjAyMTYyMjM5MTRa
GA8yMTI2MDEyMzIyMzkxNFowezELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlm
b3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xEjAQBgNVBAoMCVJOUUMgVGVz
dDEQMA4GA1UECwwHVGVzdGluZzEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMNdAMBDbRU6Sowe7xs+N2Lr
lrLXYjMjOxIm3ycfuQCK4EpmaJ+WLNctTF8DP7bfo9U0ItJawAbFdMVLWKOSzHmb
ZpCpB9qUSycBOdKgcepgHm9seoF8IdQWSXF5MNx73e6KOITPNfQ1XAQ/bcNMQ52Z
rDQBj/Usu4+VOKiL+9sjFoP8z2MLhHKrVcmuJFLmZek84wWT5zkbaBSRC4ZP6xTk
wITP5OGGmpTliZ1ZfvZ1bce+H0pPiDDJB1P1sOFhUW+f9eABUQnNUB95XnqY78Sd
zhwvgYLsBZIMFCu8tLv6TT/kp2eqIPnr7KVSI6PqVA2KeYaIzAtcJCrfyj59/0EC
AwEAAaOB+TCB9jAdBgNVHQ4EFgQUyvtMod1JR/MyOywSthOoSzudfckwHwYDVR0j
BBgwFoAUyvtMod1JR/MyOywSthOoSzudfckwQgYDVR0RBDswOYIQdGVzdC5leGFt
cGxlLmNvbYINKi5leGFtcGxlLmNvbYcEfwAAAYEQdGVzdEBleGFtcGxlLmNvbTAP
BgNVHRMBAf8EBTADAQH/MAsGA1UdDwQEAwICpDAdBgNVHSUEFjAUBggrBgEFBQcD
AQYIKwYBBQUHAwIwMwYIKwYBBQUHAQEEJzAlMCMGCCsGAQUFBzABhhdodHRwOi8v
b2NzcC5leGFtcGxlLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEARipMQsNnagHHLQxz
zSbiKKB6Qrxt0k4IwEIyIKb4daZaXw9viMkS9ULm0uHmO7HcOr6wUYdmv+swFsC
yu5E8ZgFqZHJGw62Yi6fhNSloaLNN9rYnOZfUj0aWnN0OA8vClfNom/vYTe4kENU
VTDP1dkPbo12jWJ4bOhchW28GSjU7heosi8tNsFr5H7cdAwXKnOmU0MqeJ+dHCda
1MiZWlDTeV2q8HRIKPuH5xmwgVZO3U7C85NekB7tZIvf5fArvKPRQ0/mzcvk+F6A
/tQwqNjZv+XgUNnZJkUkYAQ5nJg50Osf1oxR182oAjR2yqXL3qBUfg563wgleVFY
KxJhZsg==
-----END CERTIFICATE-----`;

const privKeyPem = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDDXQDAQ20VOkqM
Hu8bPjdi65ay12IzIzsSJt8nH7kAiuBKZmiflizXLUxfAz+236PVNCLSWsAGxXTF
S1ijksx5m2aQqQfalEsnATnSoHHqYB5vbHqBfCHUFklxeTDce93uijiEzzX0NVwE
P23DTEOdmaw0AY/1LLuPlTioi/vbIxaD/M9jC4Ryq1XJriRS5mXpPOMFk+c5G2gU
kQuGT+sU5MCEz+ThhpqU5YmdWX72dW3Hvh9KT4gwyQdT9bDhYVFvn/XgAVEJzVAf
eV56mO/Enc4cL4GC7AWSDBQrvLS7+k0/5KdnqiD56+ylUiOj6lQNinmGiMwLXCQq
38o+ff9BAgMBAAECggEAG8LeBfQu4+WAzWY3QmRLbjudvQkyk6NjKVervegEm96g
M60CG1dgRNgo3OwzGXNbLm32WspO35zJ1KAPLE4CehoKmkONcafsAVLBGudLeMDd
jPuEcbJS2PatILpWJqaqvqhr5/d3/8gLV4aEkaGHOYsqTMjst4F6n6iBQMuE57qA
+ubXy8nQD7ufSKPIxdD4jHg226m1FjiKnDArD4H1iIHC1xdt7E5FG5KRzwPFXU4B
kwSqh9GFFS7JdSoqwa+8MVZP2IHGrwpIkUnVEedgkA+pbVXFVfKvfOUUQ01t14Tc
OjT819vIj2av+yDfW5q0fUWdOQrs7ZLsVBLrazJnzwKBgQDiYCdeZCFh2T8GdYd8
ZDnpLaMrFSJAYiRXbNo1aKhLGE5gee9t0dLw5wM0ARBlXb/kCFnK5HmPi9CxukuQ
EbCqIQ1+NsQNGS307QXSoQjT38uwrlp9tROb8RdaTE9xBc9gJVEcgmPDnrY0zesE
9DrUfMR7auqyYzhWSwzuPdkvdwKBgQDc7eaVoDGf0cLfQ0ezOj5NLuLve+lza0Tf
YlC2csTpzfn0GPGZdj1MOvUFYIk/r1mPDWT0vJbtlpn73lVGypKgDEAWUYvVLaKW
escMQN9Xmf1a+0Cxi+rIFUhjkLdSAdyzGawl+7rXmDXNyFx5DWAUhQTfrF2gLbZ3
Cpgf9zqlBwKBgHsVDrK6vI/IIAVyB51xnS8UOkBleD8LXXkPXUFmywIxkAPSqITM
beW/pTU0UubaZ0gj5jZzrUiIG4tWoFkP1T9bQ0vZmRUKGLuv19ei6PrSFpzU36yz
tJq4JhtZnGP2Zb9/6q8Wkgm9lJH3WA5UgFwiDm6QPlWJrwr0OW6bwCeXAoGBAMBH
VR34M/hSiXXiim6UTFDEc8HWaFGJlIGOgYyoynRqThaB9xOG8sZ7sXAimpEQvbNh
BvJxiDHzlsS8th9MgtxEjSpfgoHgm9a3uLETbM5DOVuLvLxJd+b3ju8IrmPzNu+x
ckAEnJKy6HDW5pR8bZiuRJWe4EVeQ6XLVKbNdv7VAoGAPjEGKlGP+AVbrMQIQfEL
8AiNUKgQsaxAAQfwY3VC0kO9KoLDda/Gcq1CL3stZQplQMl0fKcNilXvHxqR+9UF
gtrj/IA4TEfNQrONszLvU5zJl4ENNLsZcEcUDVOXA+3WaNn2UZhJy8+Te8pXLhjI
FRFj+ZJzGB1ap637vnnRI+U=
-----END PRIVATE KEY-----`;

const expectedSha1 =
  'EE:E2:BF:1F:B5:0C:AF:E4:AC:27:B7:88:2F:62:55:0D:A3:46:6F:94';
const expectedSha256 =
  '0A:71:7E:E8:7B:1C:C3:A7:2D:93:E5:13:DA:B9:69:99:D3:06:56:C8:66:62:EB:A3:F6:BF:87:75:64:2F:C3:11';
const expectedSha512 =
  'BE:57:03:CD:09:14:7A:56:CB:CF:BF:57:FF:68:3A:EE:93:10:B3:04:39:C3:A9:99:1F:1B:4C:89:A2:1E:76:3B:96:49:79:6A:62:F1:F2:04:A9:6E:26:8A:0A:A4:4C:DF:C1:E9:39:25:8F:C1:D6:80:9A:20:B6:E7:2C:DC:6D:42';

// --- Construction ---

test(SUITE, 'constructs from PEM string', () => {
  const x509 = new X509Certificate(certPem);
  assert.isOk(x509);
});

test(SUITE, 'constructs from Buffer', () => {
  const x509 = new X509Certificate(Buffer.from(certPem));
  assert.isOk(x509);
});

test(SUITE, 'throws on invalid input', () => {
  assert.throws(() => {
    new X509Certificate('invalid');
  });
});

// --- String properties ---

test(SUITE, 'subject contains CN', () => {
  const x509 = new X509Certificate(certPem);
  assert.include(x509.subject, 'test.example.com');
});

test(SUITE, 'issuer matches subject (self-signed)', () => {
  const x509 = new X509Certificate(certPem);
  assert.strictEqual(x509.subject, x509.issuer);
});

test(SUITE, 'subjectAltName contains DNS entries', () => {
  const x509 = new X509Certificate(certPem);
  assert.include(x509.subjectAltName, 'test.example.com');
});

test(SUITE, 'subjectAltName contains IP', () => {
  const x509 = new X509Certificate(certPem);
  assert.include(x509.subjectAltName, '127.0.0.1');
});

test(SUITE, 'subjectAltName contains email', () => {
  const x509 = new X509Certificate(certPem);
  assert.include(x509.subjectAltName, 'test@example.com');
});

test(SUITE, 'infoAccess contains OCSP URI', () => {
  const x509 = new X509Certificate(certPem);
  assert.include(x509.infoAccess, 'ocsp.example.com');
});

test(SUITE, 'validFrom is a date string', () => {
  const x509 = new X509Certificate(certPem);
  assert.include(x509.validFrom, '2026');
});

test(SUITE, 'validTo is a date string', () => {
  const x509 = new X509Certificate(certPem);
  assert.include(x509.validTo, '2126');
});

test(SUITE, 'serialNumber is hex string', () => {
  const x509 = new X509Certificate(certPem);
  assert.strictEqual(
    x509.serialNumber,
    '617ED0A40872C25592BCC2067C885C5F21754BA9',
  );
});

test(SUITE, 'signatureAlgorithm returns algorithm name', () => {
  const x509 = new X509Certificate(certPem);
  assert.include(x509.signatureAlgorithm.toLowerCase(), 'sha256');
});

// --- Fingerprints ---

test(SUITE, 'fingerprint returns SHA-1 colon hex', () => {
  const x509 = new X509Certificate(certPem);
  assert.strictEqual(x509.fingerprint, expectedSha1);
});

test(SUITE, 'fingerprint256 returns SHA-256 colon hex', () => {
  const x509 = new X509Certificate(certPem);
  assert.strictEqual(x509.fingerprint256, expectedSha256);
});

test(SUITE, 'fingerprint512 returns SHA-512 colon hex', () => {
  const x509 = new X509Certificate(certPem);
  assert.strictEqual(x509.fingerprint512, expectedSha512);
});

// --- Date properties ---

test(SUITE, 'validFromDate returns Date object', () => {
  const x509 = new X509Certificate(certPem);
  assert.instanceOf(x509.validFromDate, Date);
  assert.strictEqual(x509.validFromDate.getUTCFullYear(), 2026);
});

test(SUITE, 'validToDate returns Date object', () => {
  const x509 = new X509Certificate(certPem);
  assert.instanceOf(x509.validToDate, Date);
  assert.strictEqual(x509.validToDate.getUTCFullYear(), 2126);
});

// --- Key & CA ---

test(SUITE, 'ca returns true for CA certificate', () => {
  const x509 = new X509Certificate(certPem);
  assert.isTrue(x509.ca);
});

test(SUITE, 'publicKey returns a key object', () => {
  const x509 = new X509Certificate(certPem);
  const pk = x509.publicKey;
  assert.strictEqual(pk.type, 'public');
});

test(SUITE, 'keyUsage returns array of strings', () => {
  const x509 = new X509Certificate(certPem);
  assert.isArray(x509.keyUsage);
  assert.isAbove(x509.keyUsage.length, 0);
});

// --- Raw/PEM ---

test(SUITE, 'raw returns DER Buffer', () => {
  const x509 = new X509Certificate(certPem);
  const raw = x509.raw;
  assert.isTrue(Buffer.isBuffer(raw));
  assert.isAbove(raw.length, 0);
});

test(SUITE, 'toString returns PEM string', () => {
  const x509 = new X509Certificate(certPem);
  assert.include(x509.toString(), '-----BEGIN CERTIFICATE-----');
});

test(SUITE, 'toJSON returns same as toString', () => {
  const x509 = new X509Certificate(certPem);
  assert.strictEqual(x509.toJSON(), x509.toString());
});

// --- Name checks ---

test(SUITE, 'checkHost matches exact hostname', () => {
  const x509 = new X509Certificate(certPem);
  assert.strictEqual(x509.checkHost('test.example.com'), 'test.example.com');
});

test(SUITE, 'checkHost returns undefined for non-matching', () => {
  const x509 = new X509Certificate(certPem);
  assert.isUndefined(x509.checkHost('wrong.example.com'));
});

test(SUITE, 'checkHost matches wildcard', () => {
  const x509 = new X509Certificate(certPem);
  assert.ok(x509.checkHost('sub.example.com'));
});

test(SUITE, 'checkEmail matches', () => {
  const x509 = new X509Certificate(certPem);
  assert.strictEqual(x509.checkEmail('test@example.com'), 'test@example.com');
});

test(SUITE, 'checkEmail returns undefined for non-matching', () => {
  const x509 = new X509Certificate(certPem);
  assert.isUndefined(x509.checkEmail('wrong@example.com'));
});

test(SUITE, 'checkIP matches 127.0.0.1', () => {
  const x509 = new X509Certificate(certPem);
  assert.strictEqual(x509.checkIP('127.0.0.1'), '127.0.0.1');
});

test(SUITE, 'checkIP returns undefined for non-matching', () => {
  const x509 = new X509Certificate(certPem);
  assert.isUndefined(x509.checkIP('192.168.1.1'));
});

// --- Verification ---

test(SUITE, 'verify with matching public key returns true', () => {
  const x509 = new X509Certificate(certPem);
  assert.isTrue(x509.verify(x509.publicKey));
});

test(SUITE, 'checkPrivateKey with matching key returns true', () => {
  const x509 = new X509Certificate(certPem);
  const privKey = createPrivateKey(privKeyPem);
  assert.isTrue(x509.checkPrivateKey(privKey));
});

test(SUITE, 'checkPrivateKey with non-matching key returns false', () => {
  const x509 = new X509Certificate(certPem);
  const { privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const otherKey = createPrivateKey(privateKey as string);
  assert.isFalse(x509.checkPrivateKey(otherKey));
});

// --- Cross-cert ---

test(SUITE, 'checkIssued returns true for self-signed', () => {
  const x509 = new X509Certificate(certPem);
  assert.isTrue(x509.checkIssued(x509));
});

test(SUITE, 'issuerCertificate returns undefined', () => {
  const x509 = new X509Certificate(certPem);
  assert.isUndefined(x509.issuerCertificate);
});

// --- Serialization ---

test(SUITE, 'toLegacyObject returns object with expected fields', () => {
  const x509 = new X509Certificate(certPem);
  const obj = x509.toLegacyObject();
  assert.isObject(obj);
  assert.property(obj, 'subject');
  assert.property(obj, 'issuer');
  assert.property(obj, 'serialNumber');
  assert.property(obj, 'fingerprint');
  assert.property(obj, 'fingerprint256');
  assert.property(obj, 'fingerprint512');
  assert.property(obj, 'valid_from');
  assert.property(obj, 'valid_to');
  assert.property(obj, 'raw');
});
