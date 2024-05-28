import { expect } from 'chai';
import { Buffer } from '@craftzdog/react-native-buffer';
import {
  fromByteArray,
  toByteArray,
  trimBase64Padding,
} from 'react-native-quick-base64';
import crypto from 'react-native-quick-crypto';
import { describe, it } from '../../MochaRNAdapter';
import { ab2str, binaryLikeToArrayBuffer } from '../../../../../src/Utils';
import { assertThrowsAsync } from '../util';
import type { JWK, KeyUsage, NamedCurve } from '../../../../../src/keys';
import type { RandomTypedArrays } from '../../../../../src/random';

const { subtle } = crypto;

// Tests that a key pair can be used for encryption / decryption.
// function testEncryptDecrypt(publicKey: any, privateKey: any) {
//   const message = 'Hello Node.js world!';
//   const plaintext = Buffer.from(message, 'utf8');
//   for (const key of [publicKey, privateKey]) {
//     const ciphertext = crypto.publicEncrypt(key, plaintext);
//     const received = crypto.privateDecrypt(privateKey, ciphertext);
//     chai.expect(received.toString('utf8')).to.equal(message);
//   }
// }

// I guess interally this functions use privateEncrypt/publicDecrypt (sign/verify)
// but the main function `sign` is not implemented yet
// Tests that a key pair can be used for signing / verification.
// function testSignVerify(publicKey: any, privateKey: any) {
//   const message = Buffer.from('Hello Node.js world!');

//   function oldSign(algo, data, key) {
//     return createSign(algo).update(data).sign(key);
//   }

//   function oldVerify(algo, data, key, signature) {
//     return createVerify(algo).update(data).verify(key, signature);
//   }

//   for (const signFn of [sign, oldSign]) {
//     const signature = signFn('SHA256', message, privateKey);
//     for (const verifyFn of [verify, oldVerify]) {
//       for (const key of [publicKey, privateKey]) {
//         const okay = verifyFn('SHA256', message, key, signature);
//         assert(okay);
//       }
//     }
//   }
// }

function base64ToArrayBuffer(val: string): ArrayBuffer {
  const arr = toByteArray(val);
  return arr.buffer;
}

// TODO: add in `url` from react-native-quick-base64 when 2.1.1 is released
function arrayBufferToBase64(buffer: ArrayBuffer, urlSafe: boolean = false) {
  var bytes = new Uint8Array(buffer);
  return fromByteArray(bytes, urlSafe);
}

describe('subtle - importKey / exportKey', () => {
  // Import/Export test bad inputs
  it('Bad inputs', async () => {
    const keyData = crypto.getRandomValues(new Uint8Array(32));
    [1, null, undefined, {}, []].map(
      async (format) =>
        await assertThrowsAsync(
          async () =>
            // @ts-expect-error
            await subtle.importKey(format, keyData, {}, false, ['wrapKey']),
          '"subtle.importKey()" is not implemented for undefined'
        )
    );
    await assertThrowsAsync(
      async () =>
        await subtle.importKey(
          // @ts-expect-error
          'not valid',
          keyData,
          { name: 'PBKDF2' },
          false,
          ['wrapKey']
        ),
      'Unsupported key usage for a PBKDF2 key'
    );
    await assertThrowsAsync(
      async () =>
        // @ts-expect-error
        await subtle.importKey('raw', 1, { name: 'PBKDF2' }, false, [
          'deriveBits',
        ]),
      'Invalid argument type for "key". Need ArrayBuffer, TypedArray, KeyObject, CryptoKey, string'
    );
    await assertThrowsAsync(
      async () =>
        await subtle.importKey(
          'raw',
          keyData,
          {
            name: 'HMAC',
          },
          false,
          ['sign', 'verify']
        ),
      '"subtle.importKey()" is not implemented for HMAC'
      // TODO: will be ERR_MISSING_OPTION or similar
    );
    await assertThrowsAsync(
      async () =>
        await subtle.importKey(
          'raw',
          keyData,
          {
            name: 'HMAC',
            hash: 'SHA-256',
          },
          false,
          ['deriveBits']
        ),
      '"subtle.importKey()" is not implemented for HMAC'
      // TODO: will be 'Unsupported key usage for an HMAC key'
    );
    await assertThrowsAsync(
      async () =>
        await subtle.importKey(
          'raw',
          keyData,
          {
            name: 'HMAC',
            hash: 'SHA-256',
            length: 0,
          },
          false,
          ['sign', 'verify']
        ),
      '"subtle.importKey()" is not implemented for HMAC'
      // TODO: will be 'Zero-length key is not supported'
    );
    await assertThrowsAsync(
      async () =>
        await subtle.importKey(
          'raw',
          keyData,
          {
            name: 'HMAC',
            hash: 'SHA-256',
            length: 1,
          },
          false,
          ['sign', 'verify']
        ),
      '"subtle.importKey()" is not implemented for HMAC'
      // TODO: will be 'Invalid key length'
    );
    await assertThrowsAsync(
      async () =>
        await subtle.importKey(
          'jwk',
          // @ts-expect-error
          null,
          {
            name: 'HMAC',
            hash: 'SHA-256',
          },
          false,
          ['sign', 'verify']
        ),
      '"subtle.importKey()" is not implemented for HMAC'
      // TODO: will be 'Invalid keyData'
    );
  });

  it('Good Input - Uint8Array', async () => {
    await subtle.importKey(
      'raw',
      new Uint8Array([
        117, 110, 102, 97, 105, 114, 32, 99, 117, 108, 116, 117, 114, 101, 32,
        115, 117, 105, 116, 32, 112, 97, 116, 104, 32, 119, 111, 114, 108, 100,
        32, 104, 105, 103, 104, 32, 116, 111, 109, 111, 114, 114, 111, 119, 32,
        118, 105, 100, 101, 111, 32, 114, 101, 99, 105, 112, 101, 32, 99, 114,
        105, 109, 101, 32, 101, 110, 103, 105, 110, 101, 32, 119, 105, 100, 116,
        104, 32, 111, 102, 116, 101, 110, 32, 116, 97, 112, 101, 32, 116, 114,
        101, 110, 100, 32, 99, 111, 112, 112, 101, 114, 32, 100, 111, 117, 98,
        108, 101, 32, 103, 108, 111, 114, 121, 32, 100, 111, 99, 116, 111, 114,
        32, 101, 110, 101, 114, 103, 121, 32, 103, 111, 111, 115, 101, 32, 115,
        101, 99, 111, 110, 100, 32, 97, 98, 115, 116, 114, 97, 99, 116, 32, 107,
        110, 111, 99, 107,
      ]),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );
  });

  // Import/Export AES Secret Key
  {
    it('AES import raw / export raw', async () => {
      const rawKeyData = crypto.getRandomValues(new Uint8Array(32));
      const keyData = binaryLikeToArrayBuffer(rawKeyData);

      // import raw
      const key = await subtle.importKey(
        'raw',
        keyData,
        { name: 'AES-CTR', length: 256 },
        true,
        ['encrypt', 'decrypt']
      );

      // export raw
      const raw = await subtle.exportKey('raw', key);
      const actual = ab2str(raw, 'hex');

      // test results
      const expected = ab2str(keyData, 'hex');
      if (actual !== expected) {
        console.log('actual  ', actual);
        console.log('expected', expected);
      }
      expect(actual).to.equal(expected, 'import raw, export raw');
    });

    it('importKey, raw, AES-GCM string algo', async () => {
      const rawKeyData = crypto.getRandomValues(new Uint8Array(32));
      const keyData = binaryLikeToArrayBuffer(rawKeyData);

      const key = await subtle.importKey('raw', keyData, 'AES-GCM', false, [
        'encrypt',
        'decrypt',
      ]);
      expect(key.keyAlgorithm.name).to.equal('AES-GCM');
      expect(key.keyAlgorithm.length).to.equal(256);
    });

    const test = (rawKeyData: RandomTypedArrays, descr: string): void => {
      it(`AES import raw / export jwk (${descr})`, async () => {
        const keyData = binaryLikeToArrayBuffer(rawKeyData);
        const keyB64 = arrayBufferToBase64(keyData, true);

        // import raw
        const key = await subtle.importKey(
          'raw',
          keyData,
          { name: 'AES-CTR', length: 256 },
          true,
          ['encrypt', 'decrypt']
        );

        // export jwk
        const jwk = await subtle.exportKey('jwk', key);
        expect(jwk.key_ops).to.have.all.members(['encrypt', 'decrypt']);
        expect(jwk.ext);
        expect(jwk.kty).to.equal('oct');
        const actual = ab2str(base64ToArrayBuffer(jwk.k));

        // test results
        const expected = ab2str(keyData, 'hex');
        if (actual !== expected) {
          console.log('actual  ', actual);
          console.log('expected', expected);
          console.log('keyB64  ', keyB64);
          console.log('jwk.k   ', jwk.k);
        }
        expect(actual).to.equal(expected, 'import raw, export jwk');

        // error, no usages
        await assertThrowsAsync(
          async () =>
            await subtle.importKey(
              'raw',
              keyData,
              { name: 'AES-GCM', length: 256 },
              true,
              [
                // empty usages
              ]
            ),
          'Usages cannot be empty when importing a secret key'
        );
      });
    };

    // test random Uint8Array
    const random = crypto.getRandomValues(new Uint8Array(32));
    test(random, 'random');

    // test while ensuring at least one of the elements is zero
    const withZero = crypto.getRandomValues(new Uint8Array(32));
    withZero[4] = 0;
    test(withZero, 'with zero');
  }

  // from https://gist.github.com/pedrouid/b4056fd1f754918ddae86b32cf7d803e#aes-gcm---importkey
  it('AES import jwk / export jwk', async () => {
    const origKey: string = 'Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE.';
    const origJwk: JWK = {
      kty: 'oct',
      k: origKey,
      alg: 'A256GCM',
      ext: true,
    };

    // import jwk
    const key = await subtle.importKey(
      'jwk',
      origJwk,
      { name: 'AES-GCM' },
      true,
      ['encrypt', 'decrypt']
    );

    // export jwk
    const jwk = await subtle.exportKey('jwk', key);
    expect(jwk.key_ops).to.have.all.members(['encrypt', 'decrypt']);
    expect(jwk.ext);
    expect(jwk.kty).to.equal('oct');
    const actual = trimBase64Padding(ab2str(base64ToArrayBuffer(jwk.k)));
    const expected = trimBase64Padding(ab2str(base64ToArrayBuffer(origKey)));
    // if (actual !== expected) {
    //   console.log('actual  ', actual);
    //   console.log('expected', expected);
    // }
    expect(actual).to.equal(expected, 'import jwk, export jwk');
  });

  // Import/Export EC Key (osp)
  it('EC import raw / export spki (osp)', async () => {
    const key = await subtle.importKey(
      'raw',
      base64ToArrayBuffer(
        'BDZRaWzATXwmOi4Y/QP3JXn8sSVSFxidMugnGf3G28snm7zek9GjT76UMhXVMEbWLxR5WG6iGTjPAKKnT3J0jCA='
      ),
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify']
    );

    const buf = await subtle.exportKey('spki', key);
    const spkiKey = arrayBufferToBase64(buf);
    expect(spkiKey).to.equal(
      'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENlFpbMBNfCY6Lhj9A/clefyxJVIXGJ0y6CcZ/cbbyyebvN6T0aNPvpQyFdUwRtYvFHlYbqIZOM8AoqdPcnSMIA=='
    );
  });

  // // TODO: enable when generateKey() is implemented
  // // from Node.js https://github.com/nodejs/node/blob/main/test/parallel/test-webcrypto-export-import.js#L217-L273
  // it('EC import / export key pairs (node)', async () => {
  //   const { publicKey, privateKey } = await subtle.generateKey({
  //     name: 'ECDSA',
  //     namedCurve: 'P-384'
  //   }, true, ['sign', 'verify']);

  //   const [
  //     spki,
  //     pkcs8,
  //     publicJwk,
  //     privateJwk,
  //   ] = await Promise.all([
  //     subtle.exportKey('spki', publicKey),
  //     subtle.exportKey('pkcs8', privateKey),
  //     subtle.exportKey('jwk', publicKey),
  //     subtle.exportKey('jwk', privateKey),
  //   ]);

  //   assert(spki);
  //   assert(pkcs8);
  //   assert(publicJwk);
  //   assert(privateJwk);

  //   const [
  //     importedSpkiPublicKey,
  //     importedPkcs8PrivateKey,
  //     importedJwkPublicKey,
  //     importedJwkPrivateKey,
  //   ] = await Promise.all([
  //     subtle.importKey('spki', spki, {
  //       name: 'ECDSA',
  //       namedCurve: 'P-384'
  //     }, true, ['verify']),
  //     subtle.importKey('pkcs8', pkcs8, {
  //       name: 'ECDSA',
  //       namedCurve: 'P-384'
  //     }, true, ['sign']),
  //     subtle.importKey('jwk', publicJwk, {
  //       name: 'ECDSA',
  //       namedCurve: 'P-384'
  //     }, true, ['verify']),
  //     subtle.importKey('jwk', privateJwk, {
  //       name: 'ECDSA',
  //       namedCurve: 'P-384'
  //     }, true, ['sign']),
  //   ]);

  //   assert(importedSpkiPublicKey);
  //   assert(importedPkcs8PrivateKey);
  //   assert(importedJwkPublicKey);
  //   assert(importedJwkPrivateKey);
  // });

  // from Node.js https://github.com/nodejs/node/blob/main/test/parallel/test-webcrypto-export-import-ec.js
  {
    type TestKeyData = {
      [key in NamedCurve]: TestKeyDatum;
    };

    type TestKeyDatum = {
      jwsAlg: string;
      spki: Buffer;
      pkcs8: Buffer;
      jwk: JWK;
    };

    type TestVector = {
      name: 'ECDH' | 'ECDSA';
      publicUsages: KeyUsage[];
      privateUsages: KeyUsage[];
    };

    const curves: NamedCurve[] = ['P-256', 'P-384', 'P-521'];

    const keyData: TestKeyData = {
      'P-521': {
        jwsAlg: 'ES512',
        spki: Buffer.from(
          '30819b301006072a8648ce3d020106052b8104002303818600040156f479f8df' +
            '1e20a7ffc04ce420c3e154ae251996bee42f034b84d41b743f34e45f311b813a' +
            '9cdec8cda59bbbbd31d460b3292521e7c1b722e5667c03db2fae753f01501736' +
            'cfe247394320d8e4afc2fd39b5a9331061b81e2241282b9e17891822b5b79e05' +
            '2f4597b59643fd39379c51bd5125c4f48bc3f025ce3cd36953286ccb38fb',
          'hex'
        ),
        pkcs8: Buffer.from(
          '3081ee020100301006072a8648ce3d020106052b810400230481d63081d3020' +
            '101044200f408758368ba930f30f76ae054fe5cd2ce7fda2c9f76a6d436cf75' +
            'd66c440bfe6331c7c172a12478193c8251487bc91263fa50217f85ff636f59c' +
            'd546e3ab483b4a1818903818600040156f479f8df1e20a7ffc04ce420c3e154' +
            'ae251996bee42f034b84d41b743f34e45f311b813a9cdec8cda59bbbbd31d46' +
            '0b3292521e7c1b722e5667c03db2fae753f01501736cfe247394320d8e4afc2' +
            'fd39b5a9331061b81e2241282b9e17891822b5b79e052f4597b59643fd39379' +
            'c51bd5125c4f48bc3f025ce3cd36953286ccb38fb',
          'hex'
        ),
        jwk: {
          kty: 'EC',
          crv: 'P-521',
          x:
            'AVb0efjfHiCn_8BM5CDD4VSuJRmWvuQvA0uE1Bt0PzTkXzEbgTqc3sjN' +
            'pZu7vTHUYLMpJSHnwbci5WZ8A9svrnU_',
          y:
            'AVAXNs_iRzlDINjkr8L9ObWpMxBhuB4iQSgrnheJGCK1t54FL0W' +
            'XtZZD_Tk3nFG9USXE9IvD8CXOPNNpUyhsyzj7',
          d:
            'APQIdYNoupMPMPdq4FT-XNLOf9osn3am1DbPddZsRAv-YzHHw' +
            'XKhJHgZPIJRSHvJEmP6UCF_hf9jb1nNVG46tIO0',
        },
      },
      'P-384': {
        jwsAlg: 'ES384',
        spki: Buffer.from(
          '3076301006072a8648ce3d020106052b8104002203620004219c14d66617b36e' +
            'c6d8856b385b73a74d344fd8ae75ef046435dda54e3b44bd5fbdebd1d08dd69e' +
            '2d7dc1dc218cb435bd28138cc778337a842f6bd61b240e74249f24667c2a5810' +
            'a76bfc28e0335f88a6501dec01976da85afb00869cb6ace8',
          'hex'
        ),
        pkcs8: Buffer.from(
          '3081b6020100301006072a8648ce3d020106052b8104002204819e30819b0201' +
            '0104304537b5990784d3c2d22e96a8f92fa1aa492ee873e576a41582e144183c' +
            '9888d10e6b9eb4ced4b2cc4012e4ac5ea84073a16403620004219c14d66617b3' +
            '6ec6d8856b385b73a74d344fd8ae75ef046435dda54e3b44bd5fbdebd1d08dd6' +
            '9e2d7dc1dc218cb435bd28138cc778337a842f6bd61b240e74249f24667c2a58' +
            '10a76bfc28e0335f88a6501dec01976da85afb00869cb6ace8',
          'hex'
        ),
        jwk: {
          kty: 'EC',
          crv: 'P-384',
          x: 'IZwU1mYXs27G2IVrOFtzp000T9iude8EZDXdpU47RL1fvevR0I3Wni19wdwhjLQ1',
          y: 'vSgTjMd4M3qEL2vWGyQOdCSfJGZ8KlgQp2v8KOAzX4imUB3sAZdtqFr7AIactqzo',
          d: 'RTe1mQeE08LSLpao-S-hqkku6HPldqQVguFEGDyYiNEOa560ztSyzEAS5KxeqEBz',
        },
      },
      'P-256': {
        jwsAlg: 'ES256',
        spki: Buffer.from(
          '3059301306072a8648ce3d020106082a8648ce3d03010703420004d6e8328a95' +
            'fe29afcdc30977b9251efbb219022807f6b14bb34695b6b4bdb93ee6684548a4' +
            'ad13c49d00433c45315e8274f3540f58f5d79ef7a1b184f4c21d17',
          'hex'
        ),
        pkcs8: Buffer.from(
          '308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02' +
            '010104202bc2eda265e46866efa8f8f99da993175b6c85c246e15dceaed7e307' +
            '0f13fbf8a14403420004d6e8328a95fe29afcdc30977b9251efbb219022807f6' +
            'b14bb34695b6b4bdb93ee6684548a4ad13c49d00433c45315e8274f3540f58f5' +
            'd79ef7a1b184f4c21d17',
          'hex'
        ),
        jwk: {
          kty: 'EC',
          crv: 'P-256',
          x: '1ugyipX-Ka_Nwwl3uSUe-7IZAigH9rFLs0aVtrS9uT4.',
          y: '5mhFSKStE8SdAEM8RTFegnTzVA9Y9dee96GxhPTCHRc.',
          d: 'K8LtomXkaGbvqPj5namTF1tshcJG4V3OrtfjBw8T-_g.',
        },
      },
    };

    const testVectors: TestVector[] = [
      {
        name: 'ECDSA',
        privateUsages: ['sign'],
        publicUsages: ['verify'],
      },
      {
        name: 'ECDH',
        privateUsages: ['deriveKey', 'deriveBits'],
        publicUsages: [],
      },
    ];

    // async function testImportSpki({ name, publicUsages }, namedCurve, extractable) {
    //   const key = await subtle.importKey(
    //     'spki',
    //     keyData[namedCurve].spki,
    //     { name, namedCurve },
    //     extractable,
    //     publicUsages);
    //   expect(key.type, 'public');
    //   expect(key.extractable, extractable);
    //   expect(key.usages).to.have.all.members(publicUsages);
    //   expect(key.algorithm.name, name);
    //   expect(key.algorithm.namedCurve, namedCurve);

    //   if (extractable) {
    //     // Test the roundtrip
    //     const spki = await subtle.exportKey('spki', key);
    //     expect(
    //       Buffer.from(spki).toString('hex'),
    //       keyData[namedCurve].spki.toString('hex'));
    //   } else {
    //     await assert.rejects(
    //       subtle.exportKey('spki', key), {
    //         message: /key is not extractable/
    //       });
    //   }

    //   // Bad usage
    //   await assert.rejects(
    //     subtle.importKey(
    //       'spki',
    //       keyData[namedCurve].spki,
    //       { name, namedCurve },
    //       extractable,
    //       ['wrapKey']),
    //     { message: /Unsupported key usage/ });
    // }

    // async function testImportPkcs8(
    //   { name, privateUsages },
    //   namedCurve,
    //   extractable) {
    //   const key = await subtle.importKey(
    //     'pkcs8',
    //     keyData[namedCurve].pkcs8,
    //     { name, namedCurve },
    //     extractable,
    //     privateUsages);
    //   expect(key.type).to.equal('private');
    //   expect(key.extractable.to.equal(extractable);
    //   expect(key.usages).to.have.all.members(privateUsages);
    //   expect(key.algorithm.name, name);
    //   expect(key.algorithm.namedCurve, namedCurve);

    //   if (extractable) {
    //     // Test the roundtrip
    //     const pkcs8 = await subtle.exportKey('pkcs8', key);
    //     expect(
    //       Buffer.from(pkcs8).toString('hex').to.equal(
    //       keyData[namedCurve].pkcs8.toString('hex'));
    //   } else {
    //     await assert.rejects(
    //       subtle.exportKey('pkcs8', key), {
    //         message: /key is not extractable/
    //       });
    //   }

    //   await assert.rejects(
    //     subtle.importKey(
    //       'pkcs8',
    //       keyData[namedCurve].pkcs8,
    //       { name, namedCurve },
    //       extractable,
    //       [// empty usages ]),
    //     { name: 'SyntaxError', message: 'Usages cannot be empty when importing a private key.' });
    // }

    const testImportJwk = async (
      { name, publicUsages, privateUsages }: TestVector,
      namedCurve: NamedCurve,
      extractable: boolean
    ) => {
      const jwk = keyData[namedCurve].jwk;

      const [publicKey, privateKey] = await Promise.all([
        subtle.importKey(
          'jwk',
          {
            kty: jwk.kty,
            crv: jwk.crv,
            x: jwk.x,
            y: jwk.y,
          },
          { name, namedCurve },
          extractable,
          publicUsages
        ),
        subtle.importKey(
          'jwk',
          jwk,
          { name, namedCurve },
          extractable,
          privateUsages
        ),
        subtle.importKey(
          'jwk',
          {
            alg: name === 'ECDSA' ? keyData[namedCurve].jwsAlg : 'ECDH-ES',
            kty: jwk.kty,
            crv: jwk.crv,
            x: jwk.x,
            y: jwk.y,
          },
          { name, namedCurve },
          extractable,
          publicUsages
        ),
        subtle.importKey(
          'jwk',
          {
            ...jwk,
            alg: name === 'ECDSA' ? keyData[namedCurve].jwsAlg : 'ECDH-ES',
          },
          { name, namedCurve },
          extractable,
          privateUsages
        ),
      ]);

      expect(publicKey.type).to.equal('public');
      expect(privateKey.type).to.equal('private');
      expect(publicKey.extractable).to.equal(extractable);
      expect(privateKey.extractable).to.equal(extractable);
      expect(publicKey.usages).to.have.all.members(publicUsages);
      expect(privateKey.usages).to.have.all.members(privateUsages);
      expect(publicKey.algorithm.name).to.equal(name);
      expect(privateKey.algorithm.name).to.equal(name);
      expect(publicKey.algorithm.namedCurve).to.equal(namedCurve);
      expect(privateKey.algorithm.namedCurve).to.equal(namedCurve);

      if (extractable) {
        // Test the round trip
        const [pubJwk, pvtJwk] = await Promise.all([
          subtle.exportKey('jwk', publicKey),
          subtle.exportKey('jwk', privateKey),
        ]);

        expect(pubJwk.key_ops).to.have.all.members(publicUsages, 'pub key_ops');
        expect(pubJwk.ext).to.equal(true, 'pub ext');
        expect(pubJwk.kty).to.equal('EC', 'pub kty');
        expect(pubJwk.x).to.equal(jwk.x, 'pub x');
        expect(pubJwk.y).to.equal(jwk.y, 'pub y');
        expect(pubJwk.crv).to.equal(jwk.crv, 'pub crv');

        expect(pvtJwk.key_ops).to.have.all.members(
          privateUsages,
          'pvt key_ops'
        );
        expect(pvtJwk.ext).to.equal(true, 'pvt ext');
        expect(pvtJwk.kty).to.equal('EC', 'pvt kty');
        expect(pvtJwk.x).to.equal(jwk.x, 'pvt x');
        expect(pvtJwk.y).to.equal(jwk.y, 'pvt y');
        expect(pvtJwk.crv).to.equal(jwk.crv, 'pvt crv');
        expect(pvtJwk.d).to.equal(jwk.d, 'pvt d');
      } else {
        await assertThrowsAsync(
          async () => await subtle.exportKey('jwk', publicKey),
          'key is not extractable'
        );
        await assertThrowsAsync(
          async () => await subtle.exportKey('jwk', privateKey),
          'key is not extractable'
        );
      }

      {
        const invalidUse = name === 'ECDH' ? 'sig' : 'enc';
        await assertThrowsAsync(
          async () =>
            await subtle.importKey(
              'jwk',
              { ...jwk, use: invalidUse },
              { name, namedCurve },
              extractable,
              privateUsages
            ),
          'Invalid JWK "use" Parameter'
        );
      }

      if (name === 'ECDSA') {
        await assertThrowsAsync(
          async () =>
            await subtle.importKey(
              'jwk',
              {
                kty: jwk.kty,
                x: jwk.x,
                y: jwk.y,
                crv: jwk.crv,
                alg: jwk.crv === 'P-256' ? 'ES384' : 'ES256',
              },
              { name, namedCurve },
              extractable,
              publicUsages
            ),
          'JWK "alg" does not match the requested algorithm'
        );

        await assertThrowsAsync(
          async () =>
            await subtle.importKey(
              'jwk',
              { ...jwk, alg: jwk.crv === 'P-256' ? 'ES384' : 'ES256' },
              { name, namedCurve },
              extractable,
              privateUsages
            ),
          'JWK "alg" does not match the requested algorithm'
        );
      }

      for (const crv of [
        undefined,
        namedCurve === 'P-256' ? 'P-384' : 'P-256',
      ]) {
        await assertThrowsAsync(
          async () =>
            await subtle.importKey(
              'jwk',
              { kty: jwk.kty, x: jwk.x, y: jwk.y, crv },
              { name, namedCurve },
              extractable,
              publicUsages
            ),
          'JWK "crv" does not match the requested algorithm'
        );

        await assertThrowsAsync(
          async () =>
            await subtle.importKey(
              'jwk',
              { ...jwk, crv },
              { name, namedCurve },
              extractable,
              privateUsages
            ),
          'JWK "crv" does not match the requested algorithm'
        );
      }

      await assertThrowsAsync(
        async () =>
          await subtle.importKey(
            'jwk',
            { ...jwk },
            { name, namedCurve },
            extractable,
            [
              // empty usages
            ]
          ),
        'Usages cannot be empty when importing a private key.'
      );
    };

    const testImportRaw = async (
      { name, publicUsages }: TestVector,
      namedCurve: NamedCurve
    ) => {
      const jwk = keyData[namedCurve].jwk;
      if (jwk.x === undefined || jwk.y === undefined) {
        throw new Error('invalid x, y args');
      }

      const [publicKey] = await Promise.all([
        subtle.importKey(
          'raw',
          Buffer.concat([
            Buffer.alloc(1, 0x04),
            toByteArray(jwk.x), // base64url?
            toByteArray(jwk.y), // base64url?
          ]),
          { name, namedCurve },
          true,
          publicUsages
        ),
        subtle.importKey(
          'raw',
          Buffer.concat([
            Buffer.alloc(1, 0x03),
            toByteArray(jwk.x), // base64url?
          ]),
          { name, namedCurve },
          true,
          publicUsages
        ),
      ]);

      expect(publicKey.type).to.equal('public');
      expect(publicKey.usages).to.have.all.members(publicUsages);
      expect(publicKey.algorithm.name).to.equal(name);
      expect(publicKey.algorithm.namedCurve).to.equal(namedCurve);
    };

    for (const vector of testVectors) {
      for (const namedCurve of curves) {
        for (const extractable of [true, false]) {
          // it(`EC spki, ${vector}, ${namedCurve}, ${extractable}`, async () => {
          //   await testImportSpki(vector, namedCurve, extractable);
          // });
          // it(`EC pkcs8, ${vector}, ${namedCurve}, ${extractable}`, async () => {
          //   await testImportPkcs8(vector, namedCurve, extractable);
          // });
          it(`EC jwk, ${vector.name}, ${namedCurve}, ${extractable}`, async () => {
            await testImportJwk(vector, namedCurve, extractable);
          });
        }
        it(`EC raw, ${vector.name}, ${namedCurve}`, async () => {
          await testImportRaw(vector, namedCurve);
        });
      }
    }
  }

  // // Import/Export HMAC Secret Key
  // // TODO: enable this after implementing HMAC import/export
  // // from Node.js https://github.com/nodejs/node/blob/main/test/parallel/test-webcrypto-export-import.js#L73-L113
  // const keyData = globalThis.crypto.getRandomValues(new Uint8Array(32));
  // const key = await subtle.importKey(
  //   'raw',
  //   keyData, {
  //     name: 'HMAC',
  //     hash: 'SHA-256'
  //   }, true, ['sign', 'verify']);

  // const raw = await subtle.exportKey('raw', key);

  // expect(
  //   Buffer.from(keyData).toString('hex')).to.equal(
  //   Buffer.from(raw).toString('hex'));

  // const jwk = await subtle.exportKey('jwk', key);
  // expect(jwk.key_ops).to.have.all.members(['sign', 'verify']);
  // assert(jwk.ext);
  // expect(jwk.kty, 'oct');

  // expect(
  // TODO: gonna be ab2str(base64toArrayBuffer(jwk.k)) like above ^^^^
  //   Buffer.from(jwk.k, 'base64').toString('hex')).to.equal(
  //   Buffer.from(raw).toString('hex'));

  // await assert.rejects(
  //   subtle.importKey(
  //     'raw',
  //     keyData,
  //     {
  //       name: 'HMAC',
  //       hash: 'SHA-256'
  //     },
  //     true,
  //     [// empty usages ]),
  //   { name: 'SyntaxError', message: 'Usages cannot be empty when importing a secret key.' });

  // Import/Export RSA Key Pairs
  // // TODO: enable when generateKey() is implemented
  // // from Node.js https://github.com/nodejs/node/blob/main/test/parallel/test-webcrypto-export-import.js#L157-L215
  // const { publicKey, privateKey } = await subtle.generateKey({
  //   name: 'RSA-PSS',
  //   modulusLength: 1024,
  //   publicExponent: new Uint8Array([1, 0, 1]),
  //   hash: 'SHA-384'
  // }, true, ['sign', 'verify']);

  // const [
  //   spki,
  //   pkcs8,
  //   publicJwk,
  //   privateJwk,
  // ] = await Promise.all([
  //   subtle.exportKey('spki', publicKey),
  //   subtle.exportKey('pkcs8', privateKey),
  //   subtle.exportKey('jwk', publicKey),
  //   subtle.exportKey('jwk', privateKey),
  // ]);

  // assert(spki);
  // assert(pkcs8);
  // assert(publicJwk);
  // assert(privateJwk);

  // const [
  //   importedSpkiPublicKey,
  //   importedPkcs8PrivateKey,
  //   importedJwkPublicKey,
  //   importedJwkPrivateKey,
  // ] = await Promise.all([
  //   subtle.importKey('spki', spki, {
  //     name: 'RSA-PSS',
  //     hash: 'SHA-384',
  //   }, true, ['verify']),
  //   subtle.importKey('pkcs8', pkcs8, {
  //     name: 'RSA-PSS',
  //     hash: 'SHA-384',
  //   }, true, ['sign']),
  //   subtle.importKey('jwk', publicJwk, {
  //     name: 'RSA-PSS',
  //     hash: 'SHA-384',
  //   }, true, ['verify']),
  //   subtle.importKey('jwk', privateJwk, {
  //     name: 'RSA-PSS',
  //     hash: 'SHA-384',
  //   }, true, ['sign']),
  // ]);

  // assert(importedSpkiPublicKey);
  // assert(importedPkcs8PrivateKey);
  // assert(importedJwkPublicKey);
  // assert(importedJwkPrivateKey);
});
