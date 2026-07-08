# Troubleshooting

## `QuickCrypto` not found

If you get an error similar to this:

```
Cannot read property 'install' of undefined
```

Then you need to install `react-native-quick-crypto` as a dependency in your `package.json` file.  Make sure to install pods (ios).

## `QuickBase64` could not be found

If your app crashes on launch with:

```
Invariant Violation: TurboModuleRegistry.getEnforcing(...): 'QuickBase64' could not be found. Verify that a module by this name is registered in the native binary.
```

This comes from `react-native-quick-base64`, which is a required dependency of `react-native-quick-crypto`. Since `1.x` of `react-native-quick-crypto` targets the New Architecture, `react-native-quick-base64` `3.0.0`+ is a pure C++ TurboModule that only registers when your app runs with the New Architecture enabled. On the Old Architecture there is no registration for `QuickBase64`, so the lookup fails and takes `react-native-quick-crypto` down with it at startup.

Fix it one of these ways:

- **Enable the New Architecture, then rebuild.**
  - Bare React Native: set `newArchEnabled=true` in `android/gradle.properties`, then `cd android && ./gradlew clean` and rebuild. (New Architecture is the default on RN `0.76`+ and required on `0.85`+.)
  - Expo: use SDK 54+, where the New Architecture is on by default, or enable it explicitly on SDK 53.
- **Stay on the Old Architecture** by pinning `react-native-quick-base64@2.2.2`, whose `2.x` line still ships the legacy Old Architecture module.

> Note: the `ndkVersion` patch that circulates for this error targets the old `react-native-quick-base64` `2.2.2` `android/build.gradle`. Version `3.0.0`+ has no `build.gradle` (it is CMake only), so that patch does not apply.

## Android build errors

If you get an error similar to this:

```
Execution failed for task ':app:mergeDebugNativeLibs'.
> A failure occurred while executing com.android.build.gradle.internal.tasks.MergeNativeLibsTask$MergeNativeLibsTaskWorkAction
   > 2 files found with path 'lib/arm64-v8a/libcrypto.so' from inputs:
      - /Users/osp/Developer/mac_test/node_modules/react-native-quick-crypto/android/build/intermediates/library_jni/debug/jni/arm64-v8a/libcrypto.so
      - /Users/osp/.gradle/caches/transforms-3/e13f88164840fe641a466d05cd8edac7/transformed/jetified-flipper-0.182.0/jni/arm64-v8a/libcrypto.so
```

It means you have a transitive dependency where two libraries depend on OpenSSL and are generating a `libcrypto.so` file. You can get around this issue by adding the following in your `app/build.gradle`:

<h4>
  React Native  <a href="#"><img src="./img/react-native.png" height="15" /></a>
</h4>

`android/app/build.gradle` file

```groovy
packagingOptions {
  // Should prevent clashes with other libraries that use OpenSSL
  pickFirst '**/libcrypto.so'
}
```

<h4>
  Expo  <a href="#"><img src="./img/expo.png" height="12" /></a>
</h4>

`app.json` file

```diff
...
  plugins: [
    ...
+   [
+     'expo-build-properties',
+     {
+       android: {
+         packagingOptions: {
+           pickFirst: ['**/libcrypto.so'],
+         },
+       },
+     },
+   ],
  ],
```

> This caused by flipper which also depends on OpenSSL

This just tells Gradle to grab whatever OpenSSL version it finds first and link against that, but as you can imagine this is not correct if the packages depend on different OpenSSL versions (quick-crypto depends on `com.android.ndk.thirdparty:openssl:1.1.1q-beta-1`). You should make sure all the OpenSSL versions match and you have no conflicts or errors.
