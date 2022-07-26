<a href="https://margelo.io">
  <img src="./img/banner.svg" width="100%" />
</a>

# ⚡️ react-native-quick-crypto

A fast implementation of Node's `crypto` module.

Unlike any other current JS-based polyfills, react-native-quick-crypto is written in C/C++ JSI and provides much greater performance - especially on mobile devices.
QuickCrypto can be used as a drop-in replacement for your Web3/Crypto apps to speed up common cryptography functions.

* 🏎️ Up to 58x faster than all other solutions
* ⚡️ Lightning fast implementation with pure C++ and JSI, instead of JS
* 🧪 Well tested in JS and C++ (OpenSSL)
* 💰 Made for crypto apps and Wallets
* 🔢 Secure native compiled cryptography
* 🔁 Easy drop-in replacement for [crypto-browserify](https://github.com/crypto-browserify/crypto-browserify) or [react-native-crypto](https://github.com/tradle/react-native-crypto)

For example, creating a Wallet using ethers.js uses complex algorithms to generate a private-key/mnemonic-phrase pair:

```ts
const start = performance.now()
const wallet = ethers.Wallet.createRandom()
const end = performance.now()
console.log(`Creating a Wallet took ${end - start} ms.`)
```

**Without** react-native-crypto 🐢:

```
Creating a Wallet took 16862 ms
```

**With** react-native-crypto ⚡️:

```
Creating a Wallet took 289 ms
```

---

## Installation

<h3>
  React Native  <a href="#"><img src="./img/react-native.png" height="15" /></a>
</h3>

```sh
yarn add react-native-quick-crypto
yarn add react-native-quick-base64
cd ios && pod install
```

<h3>
  Expo  <a href="#"><img src="./img/expo.png" height="12" /></a>
</h3>

```sh
expo install react-native-quick-crypto
expo install react-native-quick-base64
expo prebuild
```

## Replace `crypto-browserify`

If you are using a library that depends on `crypto`, instead of polyfilling it with `crypto-browserify` (or `react-native-crypto`) you can use `react-native-quick-crypto` for a fully native implementation. This way you can get much faster crypto operations with just a single-line change!

In your `babel.config.js`, add a module resolver to replace `crypto` with `react-native-quick-crypto`:

```diff
module.exports = {
  presets: ['module:metro-react-native-babel-preset'],
  plugins: [
+   [
+     'module-resolver',
+     {
+       alias: {
+         'crypto': 'react-native-quick-crypto',
+         'stream': 'stream-browserify',
+         'buffer': '@craftzdog/react-native-buffer',
+       },
+     },
+   ],
    ...
  ],
};
```

Now, all imports for `crypto` will be resolved as `react-native-quick-crypto` instead.

> 💡 Since react-native-quick-crypto depends on `stream` and `buffer`, we can resolve those to `stream-browserify` and @craftzdog's `react-native-buffer` (which is faster than `buffer` because it uses JSI for base64 encoding and decoding).

## Usage

For example, to hash a string with SHA256 you can do the following:

```ts
import Crypto from 'react-native-quick-crypto'

const hashed = Crypto.createHash('sha256')
  .update('Damn, Margelo writes hella good software!')
  .digest('hex')
```

---

## Sponsors

<!-- Onin -->
<div align="center">
<img height="50" src="./img/sponsors/onin.svg" align="center"><br/>
<a href="https://onin.co"><b>Onin</b></a> - This library is supported by Onin. Plan events without leaving the chat: <a href="https://onin.co">onin.co</a>
</div>
<br/>
<br/>

<!-- Steakwallet -->
<div align="center">
<img height="37" src="./img/sponsors/omni.png" align="center"><br/>
<a href="https://steakwallet.fi"><b>Omni</b></a> - Web3 for all. Access all of Web3 in one easy to use wallet. Omni supports more blockchains so you get more tokens, more yields, more NFTs, and more fun!
</div>
<br/>
<br/>

<!-- Litentry -->
<div align="center">
<img height="70" src="./img/sponsors/litentry.png" align="center"><br/>
<a href="https://litentry.com"><b>Litentry</b></a> - A decentralized identity aggregator, providing the structure and tools to empower you and your identity.
</div>
<br/>
<br/>

<!-- WalletConnect -->
<div align="center">
<img height="35" src="./img/sponsors/walletconnect.png" align="center"><br/>
<a href="https://walletconnect.com"><b>WalletConnect</b></a> - The communications protocol for web3, WalletConnect brings the ecosystem together by enabling wallets and apps to securely connect and interact.
</div>
<br/>
<br/>

<!-- WalletConnect -->

<!-- THORSwap -->
<div align="center">
<img height="40" src="./img/sponsors/thorswap.png" align="center"><br/>
<a href="https://thorswap.finance"><b>THORSwap</b></a> - THORSwap is a cross-chain DEX aggregator that enables users to swap native assets across chains, provide liquidity to earn yield, and more. THORSwap is fully permissionless and non-custodial. No account signup, your wallet, your keys, your coins.
</div>
<br/>
<br/>

## Limitations

As the library uses JSI for synchronous native methods access, remote debugging (e.g. with Chrome) is no longer possible. Instead, you should use [Flipper](https://fbflipper.com).

## Adopting at scale

react-native-quick-crypto was built at Margelo, an elite app development agency. For enterprise support or other business inquiries, contact us at <a href="mailto:hello@margelo.io?subject=Adopting react-native-quick-crypto at scale">hello@margelo.io</a>!

## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

## License

- react-native-quick-crypto is licensed under MIT.
- react-native-quick-crypto is heavily inspired by NodeJS Crypto, which is licensed under [nodejs/LICENSE](https://github.com/nodejs/node/blob/main/LICENSE).
