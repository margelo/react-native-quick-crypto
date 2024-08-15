<a href="https://margelo.io">
  <img src="./docs/img/banner.svg" width="100%" />
</a>

# ⚡️ react-native-quick-crypto

A fast implementation of Node's `crypto` module.

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
| `1.x`     | new [->](https://github.com/reactwg/react-native-new-architecture/blob/main/docs/enable-apps.md)  | Nitro Modules [->](https://github.com/margelo/react-native-nitro) |
| `0.x`     | old  | Bridge & JSI |

## Benchmarks

For example, creating a Wallet using ethers.js uses complex algorithms to generate a private-key/mnemonic-phrase pair:

```ts
const start = performance.now();
const wallet = ethers.Wallet.createRandom();
const end = performance.now();
console.log(`Creating a Wallet took ${end - start} ms.`);
```

**Without** react-native-quick-crypto 🐢:

```
Creating a Wallet took 16862 ms
```

**With** react-native-quick-crypto ⚡️:

```
Creating a Wallet took 289 ms
```

---

## Installation

<h3>
  React Native  <a href="#"><img src="./docs/img/react-native.png" height="15" /></a>
</h3>

```sh
yarn add react-native-quick-crypto
cd ios && pod install
```

<h3>
  Expo  <a href="#"><img src="./docs/img/expo.png" height="12" /></a>
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
+         'buffer': '@craftzdog/react-native-buffer',
+       },
+     },
+   ],
    ...
  ],
};
```

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

As the library uses JSI for synchronous native methods access, remote debugging (e.g. with Chrome) is no longer possible. Instead, you should use [Flipper](https://fbflipper.com).

Not all cryptographic algorithms are supported yet. See the [implementation coverage](./docs/implementation-coverage.md) document for more details. If you need a specific algorithm, please open a `feature request` issue and we'll see what we can do.

## Community Discord

[Join the Margelo Community Discord](https://discord.gg/6CSHz2qAvA) to chat about react-native-quick-crypto or other Margelo libraries.

## Adopting at scale

react-native-quick-crypto was built at Margelo, an elite app development agency. For enterprise support or other business inquiries, contact us at <a href="mailto:hello@margelo.io?subject=Adopting react-native-quick-crypto at scale">hello@margelo.io</a>!

## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

## License

- react-native-quick-crypto is licensed under MIT.
- react-native-quick-crypto is heavily inspired by NodeJS Crypto, which is licensed under [nodejs/LICENSE](https://github.com/nodejs/node/blob/main/LICENSE).
