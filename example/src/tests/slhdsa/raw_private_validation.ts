import { Buffer, SlhDsa } from 'react-native-quick-crypto';
import { expect } from 'chai';
import { assertThrowsAsync, test } from '../util';

const SUITE = 'SLH-DSA raw private key validation';
const error = 'SLH-DSA raw private key validation failed';

// First test in each NIST ACVP keyGen FIPS 205 group, commit 975de31eb83d87039ec88934fdc47d8c312b892d.
// https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/SLH-DSA-keyGen-FIPS205/internalProjection.json
// Source SHA-256 d7c53a1b6450087047b57aae83a5a51a0ac89ecdb23ebe071e83fbb69ae9d920.
const vectors = [
  {
    variant: 'SLH-DSA-SHA2-128s',
    testCase: 1,
    privateKey:
      '173d04c938c1c36bf289c3c022d04b1463ae23c41aa546da589774ac20b745c40d794777914c99766827f0f09ca972be0162c10219d422adba1359e6aa65299c',
    publicKey:
      '0d794777914c99766827f0f09ca972be0162c10219d422adba1359e6aa65299c',
  },
  {
    variant: 'SLH-DSA-SHAKE-128s',
    testCase: 11,
    privateKey:
      'c151951f3811029239b74add24c506afdd30363e156e6fe936ec6ed0231feb5c529ffe86200d1f32c2b60d0cd909f1900761f9b727afa724b47223016bb5b2ba',
    publicKey:
      '529ffe86200d1f32c2b60d0cd909f1900761f9b727afa724b47223016bb5b2ba',
  },
  {
    variant: 'SLH-DSA-SHA2-128f',
    testCase: 21,
    privateKey:
      'c42bcb3b5a6f331f5cce899253c6d9e29ff2b7ead7a04bab1794db8cc659c3b4a868f1bd5debc12d4c9fad66aabd0a94b546df247be4c457f3d467cdfcfabd39',
    publicKey:
      'a868f1bd5debc12d4c9fad66aabd0a94b546df247be4c457f3d467cdfcfabd39',
  },
  {
    variant: 'SLH-DSA-SHAKE-128f',
    testCase: 31,
    privateKey:
      '3956ab391b4d22fc907af0740326d061ab0eb206436f2b86ebe086d77739b3e456505c229f4e7fa6b201714c7dcc9da366578f1f24c3fe371c97c14ce0e79cdc',
    publicKey:
      '56505c229f4e7fa6b201714c7dcc9da366578f1f24c3fe371c97c14ce0e79cdc',
  },
  {
    variant: 'SLH-DSA-SHA2-192s',
    testCase: 41,
    privateKey:
      '040266529c1864088925506c20a624a2b6d50cd77c1c6f0d2841150ae8157512ef34a343ffea77ff7d9e814b45a8b41464462665f4202886206a8f632267186ca6a1cad08a2b9a862c6a7bc4ac4aaa84accef60d529f0311274f205e8da642c9',
    publicKey:
      '64462665f4202886206a8f632267186ca6a1cad08a2b9a862c6a7bc4ac4aaa84accef60d529f0311274f205e8da642c9',
  },
  {
    variant: 'SLH-DSA-SHAKE-192s',
    testCase: 51,
    privateKey:
      '8732621860e9a6e1887be55f7af692b98eb4c10b2599f94ad5cc9d6470d8b21136158e8b1710f1fbe03eced37ed4ac6853fc64d46d7e1653ebbb36ed5fbc12c6e7cef3cb756482c8c620452e864e8497e1b38a7b04449219acd9e4393f9c88ef',
    publicKey:
      '53fc64d46d7e1653ebbb36ed5fbc12c6e7cef3cb756482c8c620452e864e8497e1b38a7b04449219acd9e4393f9c88ef',
  },
  {
    variant: 'SLH-DSA-SHA2-192f',
    testCase: 61,
    privateKey:
      'a021b4b9d6dee168722bc10225e50a946642af630c3c7c7d69e3a40ba09df2ac165b792a07f064ac5fc28d8c99a580f4ee4823d09e79854706daa80ae3179b5bc8c2e9409d6328a33577fd584bc0784c559cdb2437a46f7f753c336369419acf',
    publicKey:
      'ee4823d09e79854706daa80ae3179b5bc8c2e9409d6328a33577fd584bc0784c559cdb2437a46f7f753c336369419acf',
  },
  {
    variant: 'SLH-DSA-SHAKE-192f',
    testCase: 71,
    privateKey:
      'fb7a2c2c75ce6c96b5f4328e0ab300476fc6f864cb5b0b99990ecb726ca822a4e3652dd92ec0aab7637ea41c0482ae2868dcc671e3534f81a352c275b6a25f906d2ed0ff62b8b4e398f1a9876cb082a48e9ae2c862b289486a3925cefc6ff4be',
    publicKey:
      '68dcc671e3534f81a352c275b6a25f906d2ed0ff62b8b4e398f1a9876cb082a48e9ae2c862b289486a3925cefc6ff4be',
  },
  {
    variant: 'SLH-DSA-SHA2-256s',
    testCase: 81,
    privateKey:
      'fcbf36a9807b30697be063a5105e091b412a391dd39e1326eba23cbd4096ca77ef4121c08dd71be913572f1f91e57d0acbcd5cec28539ac275832bbaa6c11081a0b4f5549ebcadb951dc2e512c76b0620d8fb8100b4ee886ef8784780d52a2543e57ab494d47068ffee4b8244aad6f19cdf94a2172bd134a15a6b5f298d5a80e',
    publicKey:
      'a0b4f5549ebcadb951dc2e512c76b0620d8fb8100b4ee886ef8784780d52a2543e57ab494d47068ffee4b8244aad6f19cdf94a2172bd134a15a6b5f298d5a80e',
  },
  {
    variant: 'SLH-DSA-SHAKE-256s',
    testCase: 91,
    privateKey:
      'e440e39644a11a6a58e850c09c8f03c273e465237f3bef7c58de62281e676cea99c199c00db30f8499a61b5b9dc8a361725f6ae80e97037176f408c30b38844dd7b5e755b4879fde3288a21af3e32fbb006fd9b8bc2b180eb9b0d82c9f3157af02acd6b3198ee1c9fe9afe61fd86d1e0877ad9061980b57b178ce27191d8eb1b',
    publicKey:
      'd7b5e755b4879fde3288a21af3e32fbb006fd9b8bc2b180eb9b0d82c9f3157af02acd6b3198ee1c9fe9afe61fd86d1e0877ad9061980b57b178ce27191d8eb1b',
  },
  {
    variant: 'SLH-DSA-SHA2-256f',
    testCase: 101,
    privateKey:
      '18523702a0fe2c9e488948b127185bab93d3f02c3d7c23a1b379f762de0509e56ab0d9f93540bd809d1d2e8a050440aa81e853750470e2b00c959dbd3be40e2bd7125f5d00ba47f1fc8d4c32c2f57c444bd384d7ce770bc50dd5980c1d1264d00ad5197ffcbaafe11b1e413f26adb1504ce1c3f5c40c1dcda14e99fd126d5b81',
    publicKey:
      'd7125f5d00ba47f1fc8d4c32c2f57c444bd384d7ce770bc50dd5980c1d1264d00ad5197ffcbaafe11b1e413f26adb1504ce1c3f5c40c1dcda14e99fd126d5b81',
  },
  {
    variant: 'SLH-DSA-SHAKE-256f',
    testCase: 111,
    privateKey:
      '2ac9403858d186b172edd8df9c78a11449893681487d3af0dad0ec341e8aca48afa2771bae6c17dd6f77b4e3808b05f56f31b8f4128df2ccb677f0283cfb18da559bc883105e8ba0264648b532626155f87edb4bedcfc12a24204d3b696d53707a158ff5d30e3428183a3b3a96a0e4a341a2a16e5a6226af374d1efb39a35df6',
    publicKey:
      '559bc883105e8ba0264648b532626155f87edb4bedcfc12a24204d3b696d53707a158ff5d30e3428183a3b3a96a0e4a341a2a16e5a6226af374d1efb39a35df6',
  },
] as const;
const reference = vectors[1];

function fixture(privateKey: string = reference.privateKey): ArrayBuffer {
  return Uint8Array.from(Buffer.from(privateKey, 'hex')).buffer;
}

// The example runner starts registered tests concurrently. Keep this process-wide
// admission contract in one test and drain every admitted job even after failure.
test(
  SUITE,
  'validates all variants and preserves bounded admission',
  async () => {
    const admitted: Promise<unknown>[] = [];
    const track = <T>(pending: Promise<T>): Promise<T> => {
      admitted.push(pending);
      return pending;
    };

    try {
      for (const vector of vectors) {
        const slh = new SlhDsa(vector.variant);
        const raw = fixture(vector.privateKey);
        const pending = track(slh.validateRawPrivateKey(raw));
        new Uint8Array(raw).fill(0);
        expect(
          Buffer.from(await pending).toString('hex'),
          `${vector.variant} NIST case ${vector.testCase}`,
        ).to.equal(vector.publicKey);
      }

      const slh = new SlhDsa(reference.variant);
      const raw = fixture();
      const bytes = new Uint8Array(raw);
      bytes[63] = bytes[63]! ^ 1;
      await assertThrowsAsync(
        () => track(slh.validateRawPrivateKey(raw)),
        error,
      );
      expect(
        Buffer.from(await track(slh.validateRawPrivateKey(fixture()))).toString(
          'hex',
        ),
      ).to.equal(reference.publicKey);

      // Capture the Promise outside the assertion to detect synchronous throws.
      const invalidSize = track(slh.validateRawPrivateKey(new ArrayBuffer(63)));
      expect(invalidSize).to.be.instanceOf(Promise);
      await assertThrowsAsync(() => invalidSize, error);

      for (const value of [null, 1, {}, new Uint8Array(64)]) {
        await assertThrowsAsync(
          async () =>
            track(slh.native.validateRawPrivateKey(value as ArrayBuffer)),
          error,
        );
      }
      for (const size of [0, 63, 65, 129]) {
        const pending = track(slh.validateRawPrivateKey(new ArrayBuffer(size)));
        await assertThrowsAsync(() => pending, error);
      }

      const captured = track(slh.validateRawPrivateKey(fixture()));
      slh.native.setVariant('SLH-DSA-SHA2-256s');
      expect(Buffer.from(await captured).toString('hex')).to.equal(
        reference.publicKey,
      );
      await assertThrowsAsync(
        () => track(slh.validateRawPrivateKey(fixture())),
        error,
      );
      slh.native.setVariant(reference.variant);
      expect(
        Buffer.from(await track(slh.validateRawPrivateKey(fixture()))).toString(
          'hex',
        ),
      ).to.equal(reference.publicKey);

      const second = new SlhDsa(reference.variant);
      const pending = track(slh.validateRawPrivateKey(fixture()));
      const overlapping = track(second.validateRawPrivateKey(fixture()));
      expect(overlapping).to.be.instanceOf(Promise);
      // The worker may finish before the next native call. Check either valid
      // outcome without relying on JS settlement timing to prove mutual exclusion.
      const [overlapResult] = await Promise.allSettled([overlapping] as const);
      if (overlapResult.status === 'fulfilled') {
        expect(Buffer.from(overlapResult.value).toString('hex')).to.equal(
          reference.publicKey,
        );
      } else {
        expect(overlapResult.reason).to.be.instanceOf(Error);
        expect((overlapResult.reason as Error).message).to.equal(error);
      }
      expect(Buffer.from(await pending).toString('hex')).to.equal(
        reference.publicKey,
      );
      expect(
        Buffer.from(
          await track(second.validateRawPrivateKey(fixture())),
        ).toString('hex'),
      ).to.equal(reference.publicKey);
    } finally {
      await Promise.allSettled(admitted);
    }
  },
);
