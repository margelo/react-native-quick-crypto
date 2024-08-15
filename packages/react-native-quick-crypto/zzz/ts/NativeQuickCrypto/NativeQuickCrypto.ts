import { NativeModules, Platform } from 'react-native';
import type { CreateHmacMethod } from './hmac';
import type { CreateHashMethod } from './hash';
import type { Pbkdf2Object } from './pbkdf2';
import type { RandomObject } from './random';
import type {
  CreateCipherMethod,
  CreateDecipherMethod,
  PublicEncryptMethod,
  PrivateDecryptMethod,
  GenerateKeyPairMethod,
  GenerateKeyPairSyncMethod,
  CreatePublicKeyMethod,
  CreatePrivateKeyMethod,
  CreateSecretKeyMethod,
} from './Cipher';
import type { CreateSignMethod, CreateVerifyMethod } from './sig';
import type { webcrypto } from './webcrypto';

interface NativeQuickCryptoSpec {
  createHmac: CreateHmacMethod;
  pbkdf2: Pbkdf2Object;
  random: RandomObject;
  createHash: CreateHashMethod;
  createCipher: CreateCipherMethod;
  createDecipher: CreateDecipherMethod;
  createPublicKey: CreatePublicKeyMethod;
  createPrivateKey: CreatePrivateKeyMethod;
  createSecretKey: CreateSecretKeyMethod;
  publicEncrypt: PublicEncryptMethod;
  publicDecrypt: PublicEncryptMethod;
  privateDecrypt: PrivateDecryptMethod;
  generateKeyPair: GenerateKeyPairMethod;
  generateKeyPairSync: GenerateKeyPairSyncMethod;
  createSign: CreateSignMethod;
  createVerify: CreateVerifyMethod;
  webcrypto: webcrypto;
}

// global func declaration for JSI functions
declare global {
  function nativeCallSyncHook(): unknown;
  var __QuickCryptoProxy: object | undefined;
}

// Check if the constructor exists. If not, try installing the JSI bindings.
if (global.__QuickCryptoProxy == null) {
  // Get the native QuickCrypto ReactModule
  const QuickCryptoModule = NativeModules.QuickCrypto;
  if (QuickCryptoModule == null) {
    let message =
      'Failed to install react-native-quick-crypto: The native `QuickCrypto` Module could not be found.';
    message +=
      '\n* Make sure react-native-quick-crypto is correctly autolinked (run `npx react-native config` to verify)';
    if (Platform.OS === 'ios' || Platform.OS === 'macos') {
      message += '\n* Make sure you ran `pod install` in the ios/ directory.';
    }
    if (Platform.OS === 'android') {
      message += '\n* Make sure gradle is synced.';
    }
    // check if Expo
    const ExpoConstants =
      NativeModules.NativeUnimoduleProxy?.modulesConstants?.ExponentConstants;
    if (ExpoConstants != null) {
      if (ExpoConstants.appOwnership === 'expo') {
        // We're running Expo Go
        throw new Error(
          'react-native-quick-crypto is not supported in Expo Go! Use EAS (`expo prebuild`) or eject to a bare workflow instead.'
        );
      } else {
        // We're running Expo bare / standalone
        message += '\n* Make sure you ran `expo prebuild`.';
      }
    }

    message += '\n* Make sure you rebuilt the app.';
    throw new Error(message);
  }

  // Check if we are running on-device (JSI)
  if (global.nativeCallSyncHook == null || QuickCryptoModule.install == null) {
    throw new Error(
      'Failed to install react-native-quick-crypto: React Native is not running on-device. QuickCrypto can only be used when synchronous method invocations (JSI) are possible. If you are using a remote debugger (e.g. Chrome), switch to an on-device debugger (e.g. Flipper) instead.'
    );
  }

  // Call the synchronous blocking install() function
  const result = QuickCryptoModule.install();
  if (result !== true)
    throw new Error(
      `Failed to install react-native-quick-crypto: The native QuickCrypto Module could not be installed! Looks like something went wrong when installing JSI bindings: ${result}`
    );

  // Check again if the constructor now exists. If not, throw an error.
  if (global.__QuickCryptoProxy == null)
    throw new Error(
      'Failed to install react-native-quick-crypto, the native initializer function does not exist. Are you trying to use QuickCrypto from different JS Runtimes?'
    );
}

const proxy = global.__QuickCryptoProxy;
export const NativeQuickCrypto = proxy as any as NativeQuickCryptoSpec;
