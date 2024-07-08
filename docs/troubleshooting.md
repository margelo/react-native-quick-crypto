# Troubleshooting

## `QuickCrypto` not found

If you get an error similar to this:

```
Cannot read property 'install' of undefined
```

Then you need to install `react-native-quick-crypto` as a dependency in your `package.json` file.  Make sure to install pods (ios).

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
