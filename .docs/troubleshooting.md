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

## `libcrypto.so` / `libssl.so` collision on Android

If a build fails like this:

```
Execution failed for task ':app:mergeDebugNativeLibs'.
   > 2 files found with path 'lib/arm64-v8a/libcrypto.so'
```

two libraries in your app are each shipping their own OpenSSL. The usual second
one is `@op-engineering/op-sqlite` with `sqlcipher: true`.

Since `1.1.7`, `react-native-quick-crypto` links OpenSSL **statically** into
`libQuickCrypto.so` and keeps its symbols off the global symbol table, so it no
longer ships `libcrypto.so` or `libssl.so` at all. Upgrading is the fix.

### On older versions

Do **not** reach for `pickFirst` on its own:

```groovy
packagingOptions {
  pickFirst '**/libcrypto.so'  // builds, then crashes at runtime
}
```

It makes the build succeed by dropping one of the two OpenSSL builds, leaving
whichever library lost the coin toss bound to a version it was not compiled
against. Expect corruption or `SIGSEGV` inside OpenSSL rather than a clean
error.

If you cannot upgrade, force both libraries onto a single OpenSSL build first,
so that whichever copy `pickFirst` keeps is the one both sides compiled against.
Both `react-native-quick-crypto` and `@op-engineering/op-sqlite` consume the
same artifact, just at different versions:

```groovy
// android/build.gradle
allprojects {
  configurations.all {
    resolutionStrategy.force 'io.github.ronickg:openssl:3.6.2-1'
  }
}
```

Pick the newest version any of your dependencies asks for — OpenSSL keeps ABI
compatibility across `3.x`, so the older consumer keeps working against the
newer build, but not the reverse.

## `libcrypto` symbol collision on iOS

The same problem has an iOS form: another dependency statically links its own
OpenSSL into your app binary, `ld` resolves each OpenSSL symbol first-wins, and
`react-native-quick-crypto` ends up calling into a foreign OpenSSL with
different struct layouts. It typically surfaces as `EXC_BAD_ACCESS` on the first
`subtle.*` call.

Since `1.1.7` this cannot happen: the bundled OpenSSL's symbols are renamed to
`rnqc_*` and the original names are local to the archive, so neither copy can
see the other. Upgrade to fix it.
