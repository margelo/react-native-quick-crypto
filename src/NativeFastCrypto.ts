import { NativeModules, Platform } from 'react-native';

// global func declaration for JSI functions
declare global {
  function nativeCallSyncHook(): unknown;
  var __FastCryptoProxy: object | undefined;
}

// Check if the constructor exists. If not, try installing the JSI bindings.
if (global.__FastCryptoProxy == null) {
  // Get the native FastCrypto ReactModule
  const FastCryptoModule = NativeModules.FastCrypto;
  if (FastCryptoModule == null) {
    let message =
      'Failed to install react-native-fast-crypto: The native `FastCrypto` Module could not be found.';
    message +=
      '\n* Make sure react-native-fast-crypto is correctly autolinked (run `npx react-native config` to verify)';
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
          'react-native-fast-crypto is not supported in Expo Go! Use EAS (`expo prebuild`) or eject to a bare workflow instead.'
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
  if (global.nativeCallSyncHook == null || FastCryptoModule.install == null) {
    throw new Error(
      'Failed to install react-native-fast-crypto: React Native is not running on-device. FastCrypto can only be used when synchronous method invocations (JSI) are possible. If you are using a remote debugger (e.g. Chrome), switch to an on-device debugger (e.g. Flipper) instead.'
    );
  }

  // Call the synchronous blocking install() function
  const result = FastCryptoModule.install();
  if (result !== true)
    throw new Error(
      `Failed to install react-native-fast-crypto: The native FastCrypto Module could not be installed! Looks like something went wrong when installing JSI bindings: ${result}`
    );

  // Check again if the constructor now exists. If not, throw an error.
  if (global.__FastCryptoProxy == null)
    throw new Error(
      'Failed to install react-native-fast-crypto, the native initializer function does not exist. Are you trying to use FastCrypto from different JS Runtimes?'
    );
}

interface NativeFastCryptoSpec {
  runAsync: () => Promise<number>;
}

const proxy = global.__FastCryptoProxy;
export const NativeFastCrypto = proxy as any as NativeFastCryptoSpec;
