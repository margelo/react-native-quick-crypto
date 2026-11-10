# 1094 — Align vendored ncrypto prime checks and empty SEC1 passphrases with Node f39899d

## Problem

Vendored ncrypto (`boorad/ncrypto` `ef5d829`) lacks two details from Node `f39899d`:

1. `BignumPointer::isPrime` does not invoke the callback between repeated `BN_check_prime()` rounds, so trial-division primes (e.g. `311`) cannot be cancelled.
2. `WriteEncryptedTraditionalPEM` hardcodes `OSSL_KEYMGMT_SELECT_KEYPAIR`; the SEC1 empty-passphrase path drops explicit-curve domain parameters.

Outcome: fork carries one compat commit with both fixes and gtest coverage; RNQC pins it and the example app covers SEC1 encrypted PEM rejections.

## Live tracker

- [x] Phase 1 — ncrypto compat commit: `isPrime` inter-round cancel, `selection` param, `tests/basic.cpp` cases (2^127-1 @ 65, 311 @ INT_MAX, explicit-curve SEC1 empty passphrase)
- [x] Phase 2 — fork publish: backup ref `backup/ef5d829`, new `rnqc/evp-only` branch, reset fork `main` to `c954a1a`
- [x] Phase 3 — RNQC submodule bump + example test (SEC1 empty/NUL passphrase round-trip, wrong and missing passphrase rejection)
- [x] Qualification (static/host) — clang-format, deprecation script, gtest; native iOS/Android runtime owned by the `/pr` attestation producer run
- [x] Independent local review (Opus): no correctness defects; fixed missing evidence SHA; fork publish done as Phase 2; two Info items skipped (explicit-curve test passes pre-fix — recorded; no PEM header assertion — low value)
- [x] Plan move
- [ ] `/pr` with signed iOS+Android attestation and screenshots — owner: orchestrator (this session)

## Decisions

- Fork layout (user, 2026-11-09): backup ref for `ef5d829`, amended single compat commit on new `rnqc/evp-only` branch based on upstream `c954a1a`, force-push fork `main` back to `c954a1a` (architecture.md mirror rule).

## Assumptions

- Amend `ef5d829` rather than stack a second commit (architecture.md: one compat commit).
- No `.gitmodules` `branch =` key; pins are by SHA.
- SELECT_ALL proof for explicit curves lives in gtest; example app covers the public named-curve path (no explicit private-key fixture exists).
- On OpenSSL 3.6.2, OSSL_KEYMGMT_SELECT_KEYPAIR already emits explicit-curve EC parameters for SEC1 type-specific encoding (gtest explicitEcSec1EncryptedPemPreservesParameters passes pre-fix); SELECT_ALL is kept for Node f39899d parity and future-OpenSSL safety.
- Example SEC1 test mirrors the RSA PKCS1 test: missing/wrong passphrase rejections are asserted only for non-empty passphrases (an empty-passphrase PEM has no meaningful missing-vs-wrong distinction).
- Podfile.lock unchanged: the QuickCrypto checksum is podspec-derived (06a2f7e9 changed it only because the podspec changed), not submodule-content-derived.

## Evidence

_(SHA — tool/test — result — platform)_

- fork boorad/ncrypto — git ls-remote + gh compare nodejs/ncrypto main...boorad:main — main=c954a1a identical; rnqc/evp-only=14d6023; backup/ef5d829 kept
- 15a3fc91 — reviewer rerun of basic gtest filter BignumPointer.*:EVPKeyPointer.explicitEcSec1* — 7/7 pass, cancel tests 0 ms — macOS host

- submodule 14d6023 — cmake (NCRYPTO_SHARED_LIBS=ON, NCRYPTO_EVP_ONLY=ON, openssl@3 3.6.2, googletest 1.18.0) + ctest — 37/37 pass; pre-fix both new prime-cancel tests fail — macOS host
- submodule 14d6023 — clang-format --style=file --dry-run --Werror src/ncrypto.cpp tests/basic.cpp include/ncrypto.h — pass
- submodule 14d6023 — OPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3 scripts/check-ncrypto-openssl-deprecations.sh — pass (default invocation picks Homebrew openssl@4 4.1.0 via pkg-config and fails on pre-existing deprecations unrelated to this diff)
- 15a3fc91 — prettier --check create_keys.ts, bun tsc, bun lint (repo root) — pass — macOS host

## Unverified


- Native runtime on iOS/Android — settled by example-app keys + prime suites after the bump.
- Deprecation script default OpenSSL discovery picks openssl@4 — pre-existing, out of scope.
- New SEC1 example assertions not yet executed in the app (tsc/lint only).
