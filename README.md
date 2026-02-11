<a href="https://margelo.com">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./.docs/img/banner-dark.png" />
    <source media="(prefers-color-scheme: light)" srcset="./.docs/img/banner-light.png" />
    <img alt="react-native-quick-crypto" src="./.docs/img/banner-light.png" />
  </picture>
</a>

# ⚡️ react-native-quick-crypto

A fast implementation of Node's `crypto` module.

> Note: This version `1.x` completed a major refactor, porting to OpenSSL 3.6+, New Architecture, Bridgeless, and [`Nitro Modules`](https://github.com/mrousavy/react-native-nitro).  It should be at or above feature-parity compared to the `0.x` version.  Status, as always, will be represented in [implementation-coverage.md](./.docs/implementation-coverage.md).

> Note: Minimum supported version of React Native is `0.75`.  If you need to use earlier versions, please use `0.x` versions of this library.

## Features

Unlike any other current JS-based polyfills, react-native-quick-crypto is written in C/C++ JSI and provides much greater performance - especially on mobile devices.
QuickCrypto can be used as a drop-in replacement for your Web3/Crypto apps to speed up common cryptography functions.

- 🏎️ Up to 58x faster than all other solutions
- ⚡️ Lightning fast implementation with pure C++ and JSI, instead of JS
- 🧪 Well tested in JS and C++ (OpenSSL)
- 💰 Made for crypto apps and Wallets
- 🔢 Secure native compiled cryptography
- 🔁 Easy drop-in replacement for [crypto-browserify](https://github.com/browserify/crypto-browserify) or [react-native-crypto](https://github.com/tradle/react-native-crypto)

## Versions

| Version | RN Architecture | Modules |
| ------- | ------ | ------- |
| `1.x`     | new [->](https://github.com/reactwg/react-native-new-architecture/blob/main/docs/enable-apps.md)  | Nitro Modules [->](https://github.com/mrousavy/nitro) |
| `0.x`     | old, new 🤞  | Bridge & JSI |

## Migration

Our goal in refactoring to v1.0 was to maintain API compatibility.  If you are upgrading to v1.0 from v0.x, and find any discrepancies, please open an issue in this repo.

## Benchmarks

There is a benchmark suite in the Example app in this repo that has benchmarks of algorithms against their pure JS counterparts.  This is not meant to disparage the other libraries.  On the contrary, they perform amazingly well when used in a server-side Node environment.  This library exists because React Native does not have that environment nor the Node Crypto API implementation at hand.  So the benchmark suite is there to show you the speedup vs. the alternative of using a pure JS library on React Native.

---

## Installation

<h3>
  React Native  <a href="#"><img src="./.docs/img/react-native.png" height="15" /></a>
</h3>

```sh
bun add react-native-quick-crypto react-native-nitro-modules react-native-quick-base64
cd ios && pod install
```

<h3>
  Expo  <a href="#">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="./.docs/img/expo/dark.png" />
      <source media="(prefers-color-scheme: light)" srcset="./.docs/img/expo/light.png" />
      <img alt="Expo" src="./.docs/img/expo/light.png" height="12" />
    </picture>
  </a>
</h3>

```sh
expo install react-native-quick-crypto
expo prebuild
```

Optional: override `global.Buffer` and `global.crypto` in your application as early as possible for example in index.js.

```ts
import { install } from 'react-native-quick-crypto';

install();
```

## Replace `crypto-browserify`

If you are using a library that depends on `crypto`, instead of polyfilling it with `crypto-browserify` (or `react-native-crypto`) you can use `react-native-quick-crypto` for a fully native implementation. This way you can get much faster crypto operations with just a single-line change!

### Using metro config

Use the [`resolveRequest`](https://facebook.github.io/metro/docs/resolution#resolverequest-customresolver) configuration option in your `metro.config.js`

```js
config.resolver.resolveRequest = (context, moduleName, platform) => {
  if (moduleName === 'crypto') {
    // when importing crypto, resolve to react-native-quick-crypto
    return context.resolveRequest(
      context,
      'react-native-quick-crypto',
      platform,
    )
  }
  // otherwise chain to the standard Metro resolver.
  return context.resolveRequest(context, moduleName, platform)
}
```

### Using babel-plugin-module-resolver

You need to install `babel-plugin-module-resolver`, it's a babel plugin that will alias any imports in the code with the values you pass to it. It tricks any module that will try to import certain dependencies with the native versions we require for React Native.

```sh
yarn add --dev babel-plugin-module-resolver
```

Then, in your `babel.config.js`, add the plugin to swap the `crypto`, `stream` and `buffer` dependencies:

```diff
module.exports = {
  presets: ['module:metro-react-native-babel-preset'],
  plugins: [
+   [
+     'module-resolver',
+     {
+       alias: {
+         'crypto': 'react-native-quick-crypto',
+         'stream': 'readable-stream',
+         'buffer': 'react-native-quick-crypto',
+       },
+     },
+   ],
    ...
  ],
};
```

> **Note:** `react-native-quick-crypto` re-exports `Buffer` from `@craftzdog/react-native-buffer`, so you can use either as the buffer alias. Using `react-native-quick-crypto` ensures a single Buffer instance across your app.

Then restart your bundler using `yarn start --reset-cache`.

## Usage

For example, to hash a string with SHA256 you can do the following:

```ts
import QuickCrypto from 'react-native-quick-crypto';

const hashed = QuickCrypto.createHash('sha256')
  .update('Damn, Margelo writes hella good software!')
  .digest('hex');
```

## Limitations

Not all cryptographic algorithms are supported yet. See the [implementation coverage](./.docs/implementation-coverage.md) document for more details. If you need a specific algorithm, please open a `feature request` issue and we'll see what we can do.

## Community Discord

[Join the Margelo Community Discord](https://discord.gg/6CSHz2qAvA) to chat about react-native-quick-crypto or other Margelo libraries.

## Adopting at scale

`react-native-quick-crypto` was built at Margelo, an elite app development agency. For enterprise support or other business inquiries, contact us at <a href="mailto:hello@margelo.io?subject=Adopting react-native-quick-crypto at scale">hello@margelo.io</a>!

## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

For more detailed guides, check out our documentation website:
- [Contributing Guide]([prod-docs]/docs/guides/contributing)
- [Writing Documentation]([prod-docs]/docs/guides/writing-documentation)

## License

- react-native-quick-crypto is licensed under MIT.
- react-native-quick-crypto is heavily inspired by NodeJS Crypto, which is licensed under [nodejs/LICENSE](https://github.com/nodejs/node/blob/main/LICENSE).
