import {
  createSign,
  createVerify,
  generateKeyPair,
} from 'react-native-quick-crypto';
import { expect } from 'chai';
import { stress } from './util';

const SUITE = 'stress.ecdsa';
const ITERATIONS = 50;
const testData = 'Stress test message for ECDSA signing';

const generateECKeyPair = (
  namedCurve: string,
): Promise<{ privateKey: string; publicKey: string }> =>
  new Promise((resolve, reject) => {
    generateKeyPair(
      'ec',
      {
        namedCurve,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      },
      (err, pubKey, privKey) => {
        if (err) reject(err);
        else
          resolve({
            privateKey: privKey as string,
            publicKey: pubKey as string,
          });
      },
    );
  });

stress(SUITE, `P-256 DER sign/verify x${ITERATIONS}`, async () => {
  const { privateKey, publicKey } = await generateECKeyPair('P-256');

  for (let i = 0; i < ITERATIONS; i++) {
    const sign = createSign('SHA256');
    sign.update(testData);
    const signature = sign.sign({ key: privateKey, dsaEncoding: 'der' });

    const verify = createVerify('SHA256');
    verify.update(testData);
    const isValid = verify.verify(
      { key: publicKey, dsaEncoding: 'der' },
      signature,
    );

    expect(isValid, `P-256 DER iteration ${i + 1}/${ITERATIONS}`).to.equal(
      true,
    );
  }
});

stress(SUITE, `P-256 IEEE-P1363 sign/verify x${ITERATIONS}`, async () => {
  const { privateKey, publicKey } = await generateECKeyPair('P-256');

  for (let i = 0; i < ITERATIONS; i++) {
    const sign = createSign('SHA256');
    sign.update(testData);
    const signature = sign.sign({
      key: privateKey,
      dsaEncoding: 'ieee-p1363',
    });

    expect(signature.length, `P-256 P1363 sig length iter ${i + 1}`).to.equal(
      64,
    );

    const verify = createVerify('SHA256');
    verify.update(testData);
    const isValid = verify.verify(
      { key: publicKey, dsaEncoding: 'ieee-p1363' },
      signature,
    );

    expect(
      isValid,
      `P-256 IEEE-P1363 iteration ${i + 1}/${ITERATIONS}`,
    ).to.equal(true);
  }
});

stress(SUITE, `P-384 DER sign/verify x${ITERATIONS}`, async () => {
  const { privateKey, publicKey } = await generateECKeyPair('P-384');

  for (let i = 0; i < ITERATIONS; i++) {
    const sign = createSign('SHA384');
    sign.update(testData);
    const signature = sign.sign({ key: privateKey, dsaEncoding: 'der' });

    const verify = createVerify('SHA384');
    verify.update(testData);
    const isValid = verify.verify(
      { key: publicKey, dsaEncoding: 'der' },
      signature,
    );

    expect(isValid, `P-384 DER iteration ${i + 1}/${ITERATIONS}`).to.equal(
      true,
    );
  }
});

stress(SUITE, `P-384 IEEE-P1363 sign/verify x${ITERATIONS}`, async () => {
  const { privateKey, publicKey } = await generateECKeyPair('P-384');

  for (let i = 0; i < ITERATIONS; i++) {
    const sign = createSign('SHA384');
    sign.update(testData);
    const signature = sign.sign({
      key: privateKey,
      dsaEncoding: 'ieee-p1363',
    });

    expect(signature.length, `P-384 P1363 sig length iter ${i + 1}`).to.equal(
      96,
    );

    const verify = createVerify('SHA384');
    verify.update(testData);
    const isValid = verify.verify(
      { key: publicKey, dsaEncoding: 'ieee-p1363' },
      signature,
    );

    expect(
      isValid,
      `P-384 IEEE-P1363 iteration ${i + 1}/${ITERATIONS}`,
    ).to.equal(true);
  }
});

stress(SUITE, `P-521 DER sign/verify x${ITERATIONS}`, async () => {
  const { privateKey, publicKey } = await generateECKeyPair('P-521');

  for (let i = 0; i < ITERATIONS; i++) {
    const sign = createSign('SHA512');
    sign.update(testData);
    const signature = sign.sign({ key: privateKey, dsaEncoding: 'der' });

    const verify = createVerify('SHA512');
    verify.update(testData);
    const isValid = verify.verify(
      { key: publicKey, dsaEncoding: 'der' },
      signature,
    );

    expect(isValid, `P-521 DER iteration ${i + 1}/${ITERATIONS}`).to.equal(
      true,
    );
  }
});

stress(SUITE, `P-521 IEEE-P1363 sign/verify x${ITERATIONS}`, async () => {
  const { privateKey, publicKey } = await generateECKeyPair('P-521');

  for (let i = 0; i < ITERATIONS; i++) {
    const sign = createSign('SHA512');
    sign.update(testData);
    const signature = sign.sign({
      key: privateKey,
      dsaEncoding: 'ieee-p1363',
    });

    expect(signature.length, `P-521 P1363 sig length iter ${i + 1}`).to.equal(
      132,
    );

    const verify = createVerify('SHA512');
    verify.update(testData);
    const isValid = verify.verify(
      { key: publicKey, dsaEncoding: 'ieee-p1363' },
      signature,
    );

    expect(
      isValid,
      `P-521 IEEE-P1363 iteration ${i + 1}/${ITERATIONS}`,
    ).to.equal(true);
  }
});

stress(SUITE, `secp256k1 DER sign/verify x${ITERATIONS}`, async () => {
  const { privateKey, publicKey } = await generateECKeyPair('secp256k1');

  for (let i = 0; i < ITERATIONS; i++) {
    const sign = createSign('SHA256');
    sign.update(testData);
    const signature = sign.sign({ key: privateKey, dsaEncoding: 'der' });

    const verify = createVerify('SHA256');
    verify.update(testData);
    const isValid = verify.verify(
      { key: publicKey, dsaEncoding: 'der' },
      signature,
    );

    expect(isValid, `secp256k1 DER iteration ${i + 1}/${ITERATIONS}`).to.equal(
      true,
    );
  }
});
