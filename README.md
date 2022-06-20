<a href="https://margelo.io">
  <img src="./img/banner.svg" width="100%" />
</a>

# ⚡️ react-native-quick-crypto

A fast implementation of Node's `crypto` module.

Unlike any other current JS-based polyfills, react-native-quick-crypto is written in C/C++ JSI and provides much greater performance - especially on mobile devices.
QuickCrypto can be used as a drop-in replacement for your Web3/Crypto apps to speed up common cryptography functions.

* 🏎️ Up to 300x faster than all other solutions
* ⚡️ Lightning fast implementation with pure C++ and JSI, instead of JS
* 🧪 Well tested in JS and C++ (OpenSSL)
* 💰 Made for crypto apps and Wallets
* 🤌 Up to 5x smaller in JS-bundle size
* 🔢 Secure native compiled cryptography
* 🔁 Easy drop-in replacement for [crypto-browserify](https://github.com/crypto-browserify/crypto-browserify) or [react-native-crypto](https://github.com/tradle/react-native-crypto)

For example, creating a Wallet using ethers.js uses complex algorithms to generate a private-key/mnemonic-phrase pair:

```ts
const start = performance.now()
const wallet = ethers.Wallet.createRandom()
const end = performance.now()
console.log(`Creating a Wallet took ${end - start}ms.`)
```

**Without** react-native-crypto 🐢:

```
Creating a Wallet took xxxms
```

**With** react-native-crypto ⚡️:

```
Creating a Wallet took yyyms
```

---

## Installation

<h3>
  React Native  <a href="#"><img src="./img/react-native.png" height="15" /></a>
</h3>

```sh
yarn add react-native-quick-crypto
cd ios && pod install
```

<h3>
  Expo  <a href="#"><img src="./img/expo.png" height="12" /></a>
</h3>

```sh
expo install react-native-quick-crypto
expo prebuild
```

## Usage

In your `metro.config.js`, add a module resolver to replace `crypto` with `react-native-quick-crypto`:

```diff
+const path = require('path');

 module.exports = {
+  resolver: {
+    extraNodeModules: {
+      crypto: path.resolve(__dirname, './node_modules/react-native-quick-crypto'),
+    },
+  },
   ...
```

Now, all imports for `crypto` will be resolved as `react-native-quick-crypto` instead.

---

## Sponsors

- TODO: List sponsors here

## Limitations

As the library uses JSI for synchronous native methods access, remote debugging (e.g. with Chrome) is no longer possible. Instead, you should use [Flipper](https://fbflipper.com).

## Adopting at scale

react-native-quick-crypto was built at Margelo, an elite app development agency. For enterprise support or other business inquiries, contact us at <a href="mailto:hello@margelo.io?subject=Adopting react-native-quick-crypto at scale">hello@margelo.io</a>!

## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

## License

MIT
