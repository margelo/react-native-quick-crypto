import { subtle, CryptoKey } from 'react-native-quick-crypto';
import { test } from '../util';
import { expect } from 'chai';

const SUITE = 'subtle.kmac';

function toHex(ab: ArrayBuffer): string {
  return Array.from(new Uint8Array(ab))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// NIST SP 800-185 test vectors
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMAC_samples.pdf
const nistVectors = [
  {
    name: 'KMAC128, no customization',
    algorithm: 'KMAC128' as const,
    key: new Uint8Array([
      0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b,
      0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
      0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    ]),
    data: new Uint8Array([0x00, 0x01, 0x02, 0x03]),
    customization: undefined as Uint8Array | undefined,
    length: 256,
    expected:
      'e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e',
  },
  {
    name: 'KMAC128, with customization',
    algorithm: 'KMAC128' as const,
    key: new Uint8Array([
      0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b,
      0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
      0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    ]),
    data: new Uint8Array([0x00, 0x01, 0x02, 0x03]),
    customization: new TextEncoder().encode('My Tagged Application'),
    length: 256,
    expected:
      '3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5',
  },
  {
    name: 'KMAC128, large data, with customization',
    algorithm: 'KMAC128' as const,
    key: new Uint8Array([
      0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b,
      0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
      0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    ]),
    data: new Uint8Array(Array.from({ length: 200 }, (_, i) => i)),
    customization: new TextEncoder().encode('My Tagged Application'),
    length: 256,
    expected:
      '1f5b4e6cca02209e0dcb5ca635b89a15e271ecc760071dfd805faa38f9729230',
  },
  {
    name: 'KMAC256, with customization, 512-bit output',
    algorithm: 'KMAC256' as const,
    key: new Uint8Array([
      0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b,
      0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
      0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    ]),
    data: new Uint8Array([0x00, 0x01, 0x02, 0x03]),
    customization: new TextEncoder().encode('My Tagged Application'),
    length: 512,
    expected:
      '20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7' +
      'f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd',
  },
  {
    name: 'KMAC256, large data, no customization, 512-bit output',
    algorithm: 'KMAC256' as const,
    key: new Uint8Array([
      0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b,
      0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
      0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    ]),
    data: new Uint8Array(Array.from({ length: 200 }, (_, i) => i)),
    customization: undefined as Uint8Array | undefined,
    length: 512,
    expected:
      '75358cf39e41494e949707927cee0af20a3ff553904c86b08f21cc414bcfd691' +
      '589d27cf5e15369cbbff8b9a4c2eb17800855d0235ff635da82533ec6b759b69',
  },
  {
    name: 'KMAC256, large data, with customization, 512-bit output',
    algorithm: 'KMAC256' as const,
    key: new Uint8Array([
      0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b,
      0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
      0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    ]),
    data: new Uint8Array(Array.from({ length: 200 }, (_, i) => i)),
    customization: new TextEncoder().encode('My Tagged Application'),
    length: 512,
    expected:
      'b58618f71f92e1d56c1b8c55ddd7cd188b97b4ca4d99831eb2699a837da2e4d9' +
      '70fbacfde50033aea585f1a2708510c32d07880801bd182898fe476876fc8965',
  },
];

// NIST test vectors via importKey + sign
for (const vec of nistVectors) {
  test(SUITE, `NIST: ${vec.name}`, async () => {
    const key = await subtle.importKey(
      'raw',
      vec.key,
      { name: vec.algorithm },
      false,
      ['sign'],
    );

    const signature = await subtle.sign(
      {
        name: vec.algorithm,
        length: vec.length,
        customization: vec.customization,
      },
      key,
      vec.data,
    );

    expect(toHex(signature)).to.equal(vec.expected);
  });
}

// NIST test vectors via importKey + verify
for (const vec of nistVectors) {
  test(SUITE, `NIST verify: ${vec.name}`, async () => {
    const key = await subtle.importKey(
      'raw',
      vec.key,
      { name: vec.algorithm },
      false,
      ['verify'],
    );

    const expectedSig = new Uint8Array(
      vec.expected.match(/.{2}/g)!.map(h => parseInt(h, 16)),
    );

    const result = await subtle.verify(
      {
        name: vec.algorithm,
        length: vec.length,
        customization: vec.customization,
      },
      key,
      expectedSig,
      vec.data,
    );

    expect(result).to.equal(true);
  });
}

// generateKey + sign + verify round-trip
for (const algorithm of ['KMAC128', 'KMAC256'] as const) {
  test(SUITE, `generateKey + sign/verify (${algorithm})`, async () => {
    const key = await subtle.generateKey({ name: algorithm }, true, [
      'sign',
      'verify',
    ]);

    const data = new TextEncoder().encode('Hello KMAC!');
    const length = algorithm === 'KMAC128' ? 256 : 512;

    const signature = await subtle.sign(
      { name: algorithm, length },
      key as CryptoKey,
      data,
    );

    expect(signature.byteLength).to.equal(length / 8);

    const valid = await subtle.verify(
      { name: algorithm, length },
      key as CryptoKey,
      signature,
      data,
    );

    expect(valid).to.equal(true);
  });
}

// verify returns false for wrong signature
test(SUITE, 'verify returns false for wrong signature', async () => {
  const key = await subtle.generateKey({ name: 'KMAC256' }, false, [
    'sign',
    'verify',
  ]);

  const data = new TextEncoder().encode('test data');

  const signature = await subtle.sign(
    { name: 'KMAC256', length: 256 },
    key as CryptoKey,
    data,
  );

  // Corrupt the signature
  const corrupted = new Uint8Array(signature);
  corrupted[0] = corrupted[0]! ^ 0xff;

  const valid = await subtle.verify(
    { name: 'KMAC256', length: 256 },
    key as CryptoKey,
    corrupted,
    data,
  );

  expect(valid).to.equal(false);
});

// importKey/exportKey round-trip (raw)
for (const algorithm of ['KMAC128', 'KMAC256'] as const) {
  test(SUITE, `import/export round-trip raw (${algorithm})`, async () => {
    const keyBytes = new Uint8Array(32);
    globalThis.crypto.getRandomValues(keyBytes);

    const key = await subtle.importKey(
      'raw',
      keyBytes,
      { name: algorithm },
      true,
      ['sign', 'verify'],
    );

    const exported = await subtle.exportKey('raw', key);
    expect(toHex(exported as ArrayBuffer)).to.equal(toHex(keyBytes.buffer));
  });
}

// importKey/exportKey round-trip (jwk)
for (const algorithm of ['KMAC128', 'KMAC256'] as const) {
  test(SUITE, `import/export round-trip jwk (${algorithm})`, async () => {
    const key = await subtle.generateKey({ name: algorithm }, true, [
      'sign',
      'verify',
    ]);

    const jwk = await subtle.exportKey('jwk', key as CryptoKey);
    const jwkObj = jwk as Record<string, unknown>;
    expect(jwkObj.alg).to.equal(algorithm === 'KMAC128' ? 'K128' : 'K256');
    expect(jwkObj.kty).to.equal('oct');

    const imported = await subtle.importKey(
      'jwk',
      jwk,
      { name: algorithm },
      true,
      ['sign', 'verify'],
    );

    // Sign with both keys and compare
    const data = new TextEncoder().encode('jwk round-trip test');
    const length = algorithm === 'KMAC128' ? 256 : 512;

    const sig1 = await subtle.sign(
      { name: algorithm, length },
      key as CryptoKey,
      data,
    );
    const sig2 = await subtle.sign({ name: algorithm, length }, imported, data);
    expect(toHex(sig1)).to.equal(toHex(sig2));
  });
}

// Different customization strings produce different output
test(SUITE, 'different customization produces different output', async () => {
  const key = await subtle.generateKey({ name: 'KMAC128' }, false, ['sign']);

  const data = new TextEncoder().encode('same data');

  const sig1 = await subtle.sign(
    {
      name: 'KMAC128',
      length: 256,
      customization: new TextEncoder().encode('App A'),
    },
    key as CryptoKey,
    data,
  );

  const sig2 = await subtle.sign(
    {
      name: 'KMAC128',
      length: 256,
      customization: new TextEncoder().encode('App B'),
    },
    key as CryptoKey,
    data,
  );

  expect(toHex(sig1)).to.not.equal(toHex(sig2));
});
