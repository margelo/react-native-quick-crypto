import {
  AsymmetricKeyObject,
  CryptoKey,
  KeyObject,
  SecretKeyObject,
  PublicKeyObject,
  PrivateKeyObject,
} from './classes';
import { generateKeyPair, generateKeyPairSync } from './generateKeyPair';
// import { sign, verify } from './signVerify';
import {
  isCryptoKey,
  parseKeyEncoding,
  parsePrivateKeyEncoding,
  parsePublicKeyEncoding,
} from './utils';

export {
  // Node Public API
  // createSecretKey,
  // createPublicKey,
  // createPrivateKey,
  CryptoKey,
  generateKeyPair,
  generateKeyPairSync,
  AsymmetricKeyObject,
  KeyObject,
  // InternalCryptoKey,
  // sign,
  // verify,

  // Node Internal API
  parsePublicKeyEncoding,
  parsePrivateKeyEncoding,
  parseKeyEncoding,
  // preparePrivateKey,
  // preparePublicOrPrivateKey,
  // prepareSecretKey,
  SecretKeyObject,
  PublicKeyObject,
  PrivateKeyObject,
  // isKeyObject,
  isCryptoKey,
  // importGenericSecretKey,
};
