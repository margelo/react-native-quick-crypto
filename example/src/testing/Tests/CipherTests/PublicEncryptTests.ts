import chai from 'chai';
import { FastCrypto as crypto } from 'react-native-fast-crypto';
import { it } from '../../MochaRNAdapter';

export function registerPublicEncryptTests() {
  it('quack', () => {
    const clearText = 'This is my random text';
    const key = 'randomKey123';

    crypto.publicEncrypt(
      {
        key,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      },
      clearText
    );

    chai.expect(true).to.equal(true);
  });
}
