import { expect } from 'chai';
import { Buffer, subtle } from 'react-native-quick-crypto';
import { test } from '../util';

// RFC 9861 §5 test vectors for TurboSHAKE128/256 and KangarooTwelve KT128/256.
// Vectors mirror Node's test/parallel/test-webcrypto-digest-turboshake-rfc.js.

const SUITE = 'subtle.digest.turboshake';

// ptn(n): RFC 9861 helper — n bytes following the pattern 00, 01, ..., F9, FA.
function ptn(n: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = i % 251;
  return out;
}

const fromHex = (hex: string): Uint8Array => {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
};

type ShakeVec = [Uint8Array, number, string, number?]; // [input, outBytes, hex, domainSeparation?]
type KtVec = [Uint8Array, number, string, Uint8Array?]; // [input, outBytes, hex, customization?]

const turboSHAKE128Vectors: ShakeVec[] = [
  [
    new Uint8Array(0),
    32,
    '1e415f1c5983aff2169217277d17bb53' + '8cd945a397ddec541f1ce41af2c1b74c',
  ],
  [
    new Uint8Array(0),
    64,
    '1e415f1c5983aff2169217277d17bb53' +
      '8cd945a397ddec541f1ce41af2c1b74c' +
      '3e8ccae2a4dae56c84a04c2385c03c15' +
      'e8193bdf58737363321691c05462c8df',
  ],
  [
    ptn(1),
    32,
    '55cedd6f60af7bb29a4042ae832ef3f5' + '8db7299f893ebb9247247d856958daa9',
  ],
  [
    ptn(17),
    32,
    '9c97d036a3bac819db70ede0ca554ec6' + 'e4c2a1a4ffbfd9ec269ca6a111161233',
  ],
  [
    ptn(17 ** 2),
    32,
    '96c77c279e0126f7fc07c9b07f5cdae1' + 'e0be60bdbe10620040e75d7223a624d2',
  ],
  [
    ptn(17 ** 3),
    32,
    'd4976eb56bcf118520582b709f73e1d6' + '853e001fdaf80e1b13e0d0599d5fb372',
  ],
  [
    fromHex('ffffff'),
    32,
    'bf323f940494e88ee1c540fe660be8a0' + 'c93f43d15ec006998462fa994eed5dab',
    0x01,
  ],
  [
    fromHex('ff'),
    32,
    '8ec9c66465ed0d4a6c35d13506718d68' + '7a25cb05c74cca1e42501abd83874a67',
    0x06,
  ],
  [
    fromHex('ffffff'),
    32,
    'b658576001cad9b1e5f399a9f77723bb' + 'a05458042d68206f7252682dba3663ed',
    0x07,
  ],
  [
    fromHex('ffffffffffffff'),
    32,
    '8deeaa1aec47ccee569f659c21dfa8e1' + '12db3cee37b18178b2acd805b799cc37',
    0x0b,
  ],
  [
    fromHex('ff'),
    32,
    '553122e2135e363c3292bed2c6421fa2' + '32bab03daa07c7d6636603286506325b',
    0x30,
  ],
  [
    fromHex('ffffff'),
    32,
    '16274cc656d44cefd422395d0f9053bd' + 'a6d28e122aba15c765e5ad0e6eaf26f9',
    0x7f,
  ],
];

const turboSHAKE256Vectors: ShakeVec[] = [
  [
    new Uint8Array(0),
    64,
    '367a329dafea871c7802ec67f905ae13' +
      'c57695dc2c6663c61035f59a18f8e7db' +
      '11edc0e12e91ea60eb6b32df06dd7f00' +
      '2fbafabb6e13ec1cc20d995547600db0',
  ],
  [
    ptn(1),
    64,
    '3e1712f928f8eaf1054632b2aa0a246e' +
      'd8b0c378728f60bc970410155c28820e' +
      '90cc90d8a3006aa2372c5c5ea176b068' +
      '2bf22bae7467ac94f74d43d39b0482e2',
  ],
  [
    ptn(17 ** 2),
    64,
    '66b810db8e90780424c0847372fdc957' +
      '10882fde31c6df75beb9d4cd9305cfca' +
      'e35e7b83e8b7e6eb4b78605880116316' +
      'fe2c078a09b94ad7b8213c0a738b65c0',
  ],
  [
    fromHex('ffffff'),
    64,
    'd21c6fbbf587fa2282f29aea620175fb' +
      '0257413af78a0b1b2a87419ce031d933' +
      'ae7a4d383327a8a17641a34f8a1d1003' +
      'ad7da6b72dba84bb62fef28f62f12424',
    0x01,
  ],
  [
    fromHex('ffffffffffffff'),
    64,
    'bb36764951ec97e9d85f7ee9a67a7718' +
      'fc005cf42556be79ce12c0bde50e5736' +
      'd6632b0d0dfb202d1bbb8ffe3dd74cb0' +
      '0834fa756cb03471bab13a1e2c16b3c0',
    0x0b,
  ],
];

const kt128Vectors: KtVec[] = [
  [
    new Uint8Array(0),
    32,
    '1ac2d450fc3b4205d19da7bfca1b3751' + '3c0803577ac7167f06fe2ce1f0ef39e5',
  ],
  [
    new Uint8Array(0),
    64,
    '1ac2d450fc3b4205d19da7bfca1b3751' +
      '3c0803577ac7167f06fe2ce1f0ef39e5' +
      '4269c056b8c82e48276038b6d292966c' +
      'c07a3d4645272e31ff38508139eb0a71',
  ],
  [
    ptn(1),
    32,
    '2bda92450e8b147f8a7cb629e784a058' + 'efca7cf7d8218e02d345dfaa65244a1f',
  ],
  [
    ptn(17),
    32,
    '6bf75fa2239198db4772e36478f8e19b' + '0f371205f6a9a93a273f51df37122888',
  ],
  [
    ptn(17 ** 2),
    32,
    '0c315ebcdedbf61426de7dcf8fb725d1' + 'e74675d7f5327a5067f367b108ecb67c',
  ],
  [
    new Uint8Array(0),
    32,
    'fab658db63e94a246188bf7af69a1330' + '45f46ee984c56e3c3328caaf1aa1a583',
    ptn(1),
  ],
  [
    fromHex('ff'),
    32,
    'd848c5068ced736f4462159b9867fd4c' + '20b808acc3d5bc48e0b06ba0a3762ec4',
    ptn(41),
  ],
  // tree-hashing path: |S| > 8192, exercises the multi-chunk branch.
  [
    ptn(8192),
    32,
    '48f256f6772f9edfb6a8b661ec92dc93' + 'b95ebd05a08a17b39ae3490870c926c3',
  ],
  [
    ptn(8192),
    32,
    '6a7c1b6a5cd0d8c9ca943a4a216cc646' + '04559a2ea45f78570a15253d67ba00ae',
    ptn(8190),
  ],
];

const kt256Vectors: KtVec[] = [
  [
    new Uint8Array(0),
    64,
    'b23d2e9cea9f4904e02bec06817fc10c' +
      'e38ce8e93ef4c89e6537076af8646404' +
      'e3e8b68107b8833a5d30490aa3348235' +
      '3fd4adc7148ecb782855003aaebde4a9',
  ],
  [
    ptn(1),
    64,
    '0d005a194085360217128cf17f91e1f7' +
      '1314efa5564539d444912e3437efa17f' +
      '82db6f6ffe76e781eaa068bce01f2bbf' +
      '81eacb983d7230f2fb02834a21b1ddd0',
  ],
  [
    ptn(17 ** 2),
    64,
    'de8ccbc63e0f133ebb4416814d4c66f6' +
      '91bbf8b6a61ec0a7700f836b086cb029' +
      'd54f12ac7159472c72db118c35b4e6aa' +
      '213c6562caaa9dcc518959e69b10f3ba',
  ],
  [
    new Uint8Array(0),
    64,
    '9280f5cc39b54a5a594ec63de0bb9937' +
      '1e4609d44bf845c2f5b8c316d72b1598' +
      '11f748f23e3fabbe5c3226ec96c62186' +
      'df2d33e9df74c5069ceecbb4dd10eff6',
    ptn(1),
  ],
  [
    ptn(8192),
    64,
    'c6ee8e2ad3200c018ac87aaa031cdac2' +
      '2121b412d07dc6e0dccbb53423747e9a' +
      '1c18834d99df596cf0cf4b8dfafb7bf0' +
      '2d139d0c9035725adc1a01b7230a41fa',
  ],
];

const toHex = (buf: ArrayBuffer): string => Buffer.from(buf).toString('hex');

turboSHAKE128Vectors.forEach(([input, outBytes, expected, ds], i) => {
  test(SUITE, `TurboSHAKE128 RFC 9861 vector ${i}`, async () => {
    const algorithm: {
      name: 'TurboSHAKE128';
      outputLength: number;
      domainSeparation?: number;
    } = { name: 'TurboSHAKE128', outputLength: outBytes * 8 };
    if (ds !== undefined) algorithm.domainSeparation = ds;
    const result = await subtle.digest(algorithm, input);
    expect(toHex(result)).to.equal(expected);
  });
});

turboSHAKE256Vectors.forEach(([input, outBytes, expected, ds], i) => {
  test(SUITE, `TurboSHAKE256 RFC 9861 vector ${i}`, async () => {
    const algorithm: {
      name: 'TurboSHAKE256';
      outputLength: number;
      domainSeparation?: number;
    } = { name: 'TurboSHAKE256', outputLength: outBytes * 8 };
    if (ds !== undefined) algorithm.domainSeparation = ds;
    const result = await subtle.digest(algorithm, input);
    expect(toHex(result)).to.equal(expected);
  });
});

kt128Vectors.forEach(([input, outBytes, expected, customization], i) => {
  test(SUITE, `KT128 RFC 9861 vector ${i}`, async () => {
    const algorithm: {
      name: 'KT128';
      outputLength: number;
      customization?: Uint8Array;
    } = { name: 'KT128', outputLength: outBytes * 8 };
    if (customization !== undefined) algorithm.customization = customization;
    const result = await subtle.digest(algorithm, input);
    expect(toHex(result)).to.equal(expected);
  });
});

kt256Vectors.forEach(([input, outBytes, expected, customization], i) => {
  test(SUITE, `KT256 RFC 9861 vector ${i}`, async () => {
    const algorithm: {
      name: 'KT256';
      outputLength: number;
      customization?: Uint8Array;
    } = { name: 'KT256', outputLength: outBytes * 8 };
    if (customization !== undefined) algorithm.customization = customization;
    const result = await subtle.digest(algorithm, input);
    expect(toHex(result)).to.equal(expected);
  });
});

// Long-output vectors that exercise the squeeze loop across multiple rate-blocks.
test(SUITE, 'TurboSHAKE128 long squeeze (10032 bytes, last 32)', async () => {
  const result = await subtle.digest(
    { name: 'TurboSHAKE128', outputLength: 10032 * 8 },
    new Uint8Array(0),
  );
  expect(Buffer.from(result).subarray(-32).toString('hex')).to.equal(
    'a3b9b0385900ce761f22aed548e754da' + '10a5242d62e8c658e3f3a923a7555607',
  );
});

test(SUITE, 'TurboSHAKE256 long squeeze (10032 bytes, last 32)', async () => {
  const result = await subtle.digest(
    { name: 'TurboSHAKE256', outputLength: 10032 * 8 },
    new Uint8Array(0),
  );
  expect(Buffer.from(result).subarray(-32).toString('hex')).to.equal(
    'abefa11630c661269249742685ec082f' + '207265dccf2f43534e9c61ba0c9d1d75',
  );
});

// Validation: WICG WebCrypto Modern Algos requires outputLength multiple of 8.
test(SUITE, 'TurboSHAKE rejects non-byte-aligned outputLength', async () => {
  let threw = false;
  try {
    await subtle.digest(
      { name: 'TurboSHAKE128', outputLength: 17 },
      new Uint8Array(0),
    );
  } catch (err) {
    threw = true;
    expect((err as Error).name).to.equal('OperationError');
  }
  expect(threw).to.equal(true);
});

test(
  SUITE,
  'TurboSHAKE rejects domainSeparation outside 0x01..0x7F',
  async () => {
    let threw = false;
    try {
      await subtle.digest(
        { name: 'TurboSHAKE128', outputLength: 256, domainSeparation: 0x80 },
        new Uint8Array(0),
      );
    } catch (err) {
      threw = true;
      expect((err as Error).name).to.equal('OperationError');
    }
    expect(threw).to.equal(true);
  },
);

test(SUITE, 'KangarooTwelve rejects missing outputLength', async () => {
  let threw = false;
  try {
    // outputLength deliberately omitted — required by WICG WebCrypto Modern
    // Algos draft and Node webidl.js:880-897.
    await subtle.digest({ name: 'KT128' }, new Uint8Array(0));
  } catch (err) {
    threw = true;
    expect((err as Error).name).to.equal('OperationError');
  }
  expect(threw).to.equal(true);
});
