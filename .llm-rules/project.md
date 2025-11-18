---
trigger: always_on
---

# React Native Quick Crypto

Every time you choose to apply a rule(s), explicitly state the rule(s) in the output. You can abbreviate the rule description to a single word or phrase.

## Project Context

- This is a React Native project that offers cryptographic operations in native code.
- It uses Nitro Modules to bridge JS & C++.
- Use the documentation of Nitro Modules if you have access locally to its `llms.txt` file.
- Part of the API strives to be a polyfill of the Node.js `{crypto}` module.
- When in doubt, favor in order: WebCrypto API, NodeJS implementation, 0.x implementation
- The goal is to migrate 0.x of this library that uses OpenSSL 1.1.1 to now use OpenSSL 3.3 and modern C++ with Nitro Modules.
- NodeJS code has the `deps/ncrypto` library where they are externalizing cryptography code using OpenSSL from the main guts of Node.  Try to use this before anything else when adding new features and/or troubleshooting.  It may still need upgrading to OpenSSL 3.3+

## Tech Stack

- React Native
- TypeScript
- Nitro Modules
- C++ 20 and higher, modern
- OpenSSL 3.3 and higher
- TypeScript package manager is `bun` 1.2 or higher

## Rules

- Attempt to reduce the amount of code rather than add more.
- Prefer iteration and modularization over code duplication.
- Do not add comments unless explicitly told to do so, or the code is sufficiently complex to warrant comments.
- Don't ask to run tests. They have to be run in an example React Native app.

