# C++ Rules

Applies to `*.cpp`, `*.hpp`, `*.h`, and `*.cc`.

## Blocking

- C++20 minimum.
- Use RAII for every resource.
- Use smart pointers for ownership.
- Raw pointers are non-owning only.
- Use OpenSSL 3.6+ EVP/provider APIs only.
- Do not use deprecated low-level APIs like `AES_*`, `SHA256_*`, or direct struct access.

## OpenSSL

- Prefer `EVP_*` APIs.
- Check all OpenSSL return values.
- Use `ERR_get_error()` for details.
- Clear/handle the error queue appropriately.
- Wrap OpenSSL resources in smart pointers with custom deleters.

Example:

```cpp
auto ctx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(
    EVP_CIPHER_CTX_new(),
    EVP_CIPHER_CTX_free);
```

## Quality

- No leaks, use-after-free, double-free, or buffer overruns.
- Keep code minimal and modular.
- Use const correctness and `constexpr` where useful.
- Comments only for complex algorithms.
- Optimize Nitro conversions and mobile performance.

## References

- Primary: `$REPOS/node/deps/ncrypto`.
- Secondary: OpenSSL 3.6+ docs and migration guides.
- Nitro docs/llms files when available.

## Formatting

- Run `clang-format -i` on modified C++ files before committing.
- Pre-commit enforces clang-format.
