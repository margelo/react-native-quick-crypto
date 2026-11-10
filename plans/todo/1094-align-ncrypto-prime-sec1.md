# 1094 — Align vendored ncrypto prime checks and empty SEC1 passphrases with Node f39899d

## Problem

Vendored ncrypto (`boorad/ncrypto` `ef5d829`) lacks two details from Node `f39899d`:

1. `BignumPointer::isPrime` does not invoke the callback between repeated `BN_check_prime()` rounds, so trial-division primes (e.g. `311`) cannot be cancelled.
2. `WriteEncryptedTraditionalPEM` hardcodes `OSSL_KEYMGMT_SELECT_KEYPAIR`; the SEC1 empty-passphrase path drops explicit-curve domain parameters.

Outcome: fork carries one compat commit with both fixes and gtest coverage; RNQC pins it and the example app covers SEC1 encrypted PEM rejections.

## Live tracker

- [ ] Phase 1 — ncrypto compat commit: `isPrime` inter-round cancel, `selection` param, `tests/basic.cpp` cases (2^127-1 @ 65, 311 @ INT_MAX, explicit-curve SEC1 empty passphrase)
- [ ] Phase 2 — fork publish: backup ref `backup/ef5d829`, new `rnqc/evp-only` branch, reset fork `main` to `c954a1a`
- [ ] Phase 3 — RNQC submodule bump + example test (SEC1 empty/NUL passphrase round-trip, wrong and missing passphrase rejection)
- [ ] Qualification — clang-format, deprecation script, gtest, native builds, example-app keys/prime suites
- [ ] Independent local review
- [ ] Plan move + `/pr`

## Decisions

- Fork layout (user, 2026-11-09): backup ref for `ef5d829`, amended single compat commit on new `rnqc/evp-only` branch based on upstream `c954a1a`, force-push fork `main` back to `c954a1a` (architecture.md mirror rule).

## Assumptions

- Amend `ef5d829` rather than stack a second commit (architecture.md: one compat commit).
- No `.gitmodules` `branch =` key; pins are by SHA.
- SELECT_ALL proof for explicit curves lives in gtest; example app covers the public named-curve path (no explicit private-key fixture exists).

## Evidence

_(SHA — tool/test — result — platform)_

## Unverified

- Native runtime on iOS/Android — settled by example-app keys + prime suites after the bump.
