# CI Caching Rules

Use when editing GitHub Actions or CI caching.

## References

- `$REPOS/nitro`: fast iOS build caching, especially `.github/workflows/build-ios.yml`.
- `$REPOS/spicy`: historical Android E2E and caching patterns only; do not replace RNQC's repository-local runner or import Spicy services and scripts.

## Blocking

- Pods cache must be exact-match only. No restore-keys.
- DerivedData cache key must be a superset of the Pods cache key.
- Restore DerivedData after `pod install`.
- Use content-addressed cache keys with `hashFiles()`.
- Do not use `github.run_id` for primary cache keys.
- Do not add version suffixes like `v2`; purge bad caches with `gh cache delete --all`.

## Cache Key Guidance

- Use lock files: `Podfile.lock`, `Gemfile.lock`, `bun.lock`.
- Include Xcode version in DerivedData keys.
- Use `actions/cache@v5`.
- Restore-keys are useful for DerivedData, not Pods.

Example:

```text
Pods: runner.os-pods-${{ hashFiles('example/ios/Podfile.lock', 'example/Gemfile.lock') }}
DD:   runner.os-dd-${{ hashFiles('...lockfiles...') }}-xcode26.2
```

## Debugging

```bash
gh run list --branch BRANCH --limit 5
gh run view RUN_ID --log-failed
gh run download RUN_ID --name ARTIFACT -D /tmp/output
gh cache list
gh cache delete --all
```

## Targets

- iOS incremental: under 2 minutes.
- Android incremental: under 3 minutes.
- Full iOS no-cache: about 15-20 minutes.
- Full Android no-cache: about 10 minutes.
