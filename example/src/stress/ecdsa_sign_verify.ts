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

const derStress = (curve: string, hash: string) => {
  stress(SUITE, `${curve} DER sign/verify x${ITERATIONS}`, async () => {
    const { privateKey, publicKey } = await generateECKeyPair(curve);

    for (let i = 0; i < ITERATIONS; i++) {
      const sign = createSign(hash);
      sign.update(testData);
      const signature = sign.sign({ key: privateKey, dsaEncoding: 'der' });

      const verify = createVerify(hash);
      verify.update(testData);
      const isValid = verify.verify(
        { key: publicKey, dsaEncoding: 'der' },
        signature,
      );

      expect(isValid, `${curve} DER iteration ${i + 1}/${ITERATIONS}`).to.equal(
        true,
      );
    }
  });
};

const p1363Stress = (curve: string, hash: string, expectedSigLen: number) => {
  stress(SUITE, `${curve} IEEE-P1363 sign/verify x${ITERATIONS}`, async () => {
    const { privateKey, publicKey } = await generateECKeyPair(curve);

    for (let i = 0; i < ITERATIONS; i++) {
      const sign = createSign(hash);
      sign.update(testData);
      const signature = sign.sign({
        key: privateKey,
        dsaEncoding: 'ieee-p1363',
      });

      expect(
        signature.length,
        `${curve} P1363 sig length iter ${i + 1}`,
      ).to.equal(expectedSigLen);

      const verify = createVerify(hash);
      verify.update(testData);
      const isValid = verify.verify(
        { key: publicKey, dsaEncoding: 'ieee-p1363' },
        signature,
      );

      expect(
        isValid,
        `${curve} IEEE-P1363 iteration ${i + 1}/${ITERATIONS}`,
      ).to.equal(true);
    }
  });
};

// P-256 (32-byte field size -> 64-byte P1363 signature)
derStress('P-256', 'SHA256');
p1363Stress('P-256', 'SHA256', 64);

// P-384 (48-byte field size -> 96-byte P1363 signature)
derStress('P-384', 'SHA384');
p1363Stress('P-384', 'SHA384', 96);

// P-521 (66-byte field size -> 132-byte P1363 signature)
derStress('P-521', 'SHA512');
p1363Stress('P-521', 'SHA512', 132);

// secp256k1 (32-byte field size -> 64-byte P1363 signature)
derStress('secp256k1', 'SHA256');
p1363Stress('secp256k1', 'SHA256', 64);
