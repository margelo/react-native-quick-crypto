# ⚡️ react-native-jsi-crypto

A fast implementation of Node's `crypto` module written in C/C++ JSI.

JSICrypto can be used as a drop-in replacement for your Web3/Crypto apps to speed up all cryptography functions.

For example, creating a Wallet using ethers.js uses complex algorithms to generate a private-key/mnemonic-phrase pair:

```ts
const start = performance.now()
const wallet = ethers.Wallet.createRandom()
const end = performance.now()
console.log(`Creating a Wallet took ${end - start}ms.`)
```

**Without** react-native-jsi-crypto 🐢:

```
Creating a Wallet took 31.3582738422ms
```

**With** react-native-jsi-crypto ⚡️:

```
Creating a Wallet took 2.47425001859ms
```

---

## Installation

### React Native

```sh
yarn add react-native-jsi-crypto
cd ios && pod install
```

### Expo

```sh
expo install react-native-jsi-crypto
expo prebuild
```

## Usage

In your `metro.config.js`, add a module resolver to replace `crypto` with `react-native-jsi-crypto`:

```diff
+const path = require('path');

 module.exports = {
+  resolver: {
+    extraNodeModules: {
+      crypto: path.resolve(__dirname, './node_modules/react-native-jsi-crypto'),
+    },
+  },
   ...
```

Now, all imports for `crypto` will be resolved as `react-native-jsi-crypto` instead.

---

## Sponsors

- TODO: List sponsors here

## Limitations

As the library uses JSI for synchronous native methods access, remote debugging (e.g. with Chrome) is no longer possible. Instead, you should use [Flipper](https://fbflipper.com).

## Adopting at scale

react-native-jsi-crypto was built at Margelo, an elite app development agency. For enterprise support or other business inquiries, contact us at <a href="mailto:hello@margelo.io?subject=Adopting react-native-jsi-crypto at scale">hello@margelo.io</a>!

## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

## License

MIT
