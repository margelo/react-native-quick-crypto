# react-native-fast-crypto

A fast implementation of Node's `crypto` module written in C/C++ JSI.

FastCrypto can be used as a drop-in replacement for your Web3/Crypto apps to speed up all cryptography functions.

## Installation

### React Native

```sh
yarn add react-native-fast-crypto
cd ios && pod install
```

### Expo

```sh
expo install react-native-fast-crypto
expo prebuild
```

## Usage

In your `metro.config.js`, add a module resolver to replace `crypto` with `react-native-fast-crypto`:

```diff
+ const path = require('path');

  module.exports = {
+   resolver: {
+     extraNodeModules: {
+       crypto: path.resolve(__dirname, './node_modules/react-native-fast-crypto'),
+     },
+   },
    transformer: {
      getTransformOptions: async () => ({
        transform: {
          experimentalImportSupport: true,
          inlineRequires: true,
        },
      }),
    },
  };
```

## Sponsors

- TODO: List sponsors here

## Limitations

As the library uses JSI for synchronous native methods access, remote debugging (e.g. with Chrome) is no longer possible. Instead, you should use [Flipper](https://fbflipper.com).

## Adopting at scale

react-native-fast-crypto was built at Margelo, an elite app development agency. For enterprise support or other business inquiries, contact us at <a href="mailto:hello@margelo.io?subject=Adopting react-native-fast-crypto at scale">hello@margelo.io</a>!

## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

## License

MIT
