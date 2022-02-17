# react-native-fast-crypto

A fast implementation of Node's `crypto` module written in C/C++ JSI.

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

TODO: Show how to replace `crypto` module with `react-native-fast-crypto` in every file (babel/metro module resolver?)

```js
import "react-native-fast-crypto/shim"
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
