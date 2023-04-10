import chai from 'chai';
import type { Buffer } from '@craftzdog/react-native-buffer';
import { it } from '../../MochaRNAdapter';
import crypto from 'react-native-quick-crypto';

// Constructs a regular expression for a PEM-encoded key with the given label.
function getRegExpForPEM(label: string, cipher?: string | null) {
  const head = `\\-\\-\\-\\-\\-BEGIN ${label}\\-\\-\\-\\-\\-`;
  const rfc1421Header =
    cipher == null
      ? ''
      : `\nProc-Type: 4,ENCRYPTED\nDEK-Info: ${cipher},[^\n]+\n`;
  const body = '([a-zA-Z0-9\\+/=]{64}\n)*[a-zA-Z0-9\\+/=]{1,64}';
  const end = `\\-\\-\\-\\-\\-END ${label}\\-\\-\\-\\-\\-`;
  return new RegExp(`^${head}${rfc1421Header}\n${body}\n${end}\n$`);
}

function assertApproximateSize(key: 'string' | Buffer, expectedSize: number) {
  const u = typeof key === 'string' ? 'chars' : 'bytes';
  const min = Math.floor(0.9 * expectedSize);
  const max = Math.ceil(1.1 * expectedSize);
  chai.assert(
    key.length >= min,
    `Key (${key.length} ${u}) is shorter than expected (${min} ${u})`
  );
  chai.assert(
    key.length <= max,
    `Key (${key.length} ${u}) is longer than expected (${max} ${u})`
  );
}

const pkcs1PubExp = getRegExpForPEM('RSA PUBLIC KEY');
// const pkcs1PrivExp = getRegExpForPEM('RSA PRIVATE KEY');
// const pkcs1EncExp = (cipher) => getRegExpForPEM('RSA PRIVATE KEY', cipher);
const spkiExp = getRegExpForPEM('PUBLIC KEY');
const pkcs8Exp = getRegExpForPEM('PRIVATE KEY');
const pkcs8EncExp = getRegExpForPEM('ENCRYPTED PRIVATE KEY');
// const sec1Exp = getRegExpForPEM('EC PRIVATE KEY');
// const sec1EncExp = (cipher) => getRegExpForPEM('EC PRIVATE KEY', cipher);

export function registerGenerateKeyPairTests() {
  it('Sync RSA: spki - pkcs8/aes-256-cbc/passphrase', () => {
    const ret = crypto.generateKeyPairSync('rsa', {
      modulusLength: 4096,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
        cipher: 'aes-256-cbc',
        passphrase: 'top secret',
      },
    });

    chai.assert.strictEqual(Object.keys(ret).length, 2);
    const { publicKey, privateKey } = ret;
    chai.expect(!!publicKey).to.equal(true);
    chai.expect(!!privateKey).to.equal(true);

    chai.assert.strictEqual(typeof publicKey, 'string');
    chai.assert.match(publicKey as any, spkiExp);
    assertApproximateSize(publicKey, 800);
    chai.assert.strictEqual(typeof privateKey, 'string');
    chai.assert.match(privateKey as any, pkcs8EncExp);
    assertApproximateSize(privateKey, 3434);
  });

  it('Sync RSA: pkcs1/pkcs8', () => {
    // To make the test faster, we will only test sync key generation once and
    // with a relatively small key.
    const ret = crypto.generateKeyPairSync('rsa', {
      publicExponent: 3,
      modulusLength: 512,
      publicKeyEncoding: {
        type: 'pkcs1',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
      },
    });

    chai.assert.strictEqual(Object.keys(ret).length, 2);
    const { publicKey, privateKey } = ret;

    chai.assert.strictEqual(typeof publicKey, 'string');
    chai.assert.match(publicKey, pkcs1PubExp);
    assertApproximateSize(publicKey, 162);
    chai.assert.strictEqual(typeof privateKey, 'string');
    chai.assert.match(privateKey, pkcs8Exp);
    assertApproximateSize(privateKey, 512);
  });

  it('Async RSA: spki - pkcs8/aes-256-cbc/passphrase', (done) => {
    crypto.generateKeyPair(
      'rsa',
      {
        modulusLength: 4096,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem',
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem',
          cipher: 'aes-256-cbc',
          passphrase: 'top secret',
        },
      },
      (err, publicKey, privateKey) => {
        if (err) {
          chai.assert.fail((err as any).toString());
        }
        chai.expect(!!publicKey).to.equal(true);
        chai.expect(!!privateKey).to.equal(true);

        // chai.assert.strictEqual(Object.keys(ret).length, 2);
        // const { publicKey, privateKey } = ret;

        chai.assert.strictEqual(typeof publicKey, 'string');
        chai.assert.match(publicKey as any, spkiExp);
        // chai.assertApproximateSize(publicKey, 162);
        chai.assert.strictEqual(typeof privateKey, 'string');
        chai.assert.match(privateKey as any, pkcs8EncExp);
        // chai.assertApproximateSize(privateKey, 512);

        done();
      }
    );
  });
}
