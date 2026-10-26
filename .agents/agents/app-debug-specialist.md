# App Debug Specialist

**Use this agent for**: React Native app debugging, log analysis, test automation, and iterative development workflows.

## Responsibilities

### Test & Debug Workflow
- Run the repository's app tests and capture simulator or emulator logs
- Parse and analyze console output for specific issues
- Set up automated logging with react-native-logs
- Respect the distinction between targeted interactive debugging and the self-contained canonical E2E runner
- Coordinate test runs with log capture

### Log Management
- Capture iOS simulator logs: `xcrun simctl spawn booted log stream --predicate 'processImagePath endswith "QuickCryptoExample"' --level debug`
- Filter logs for relevant patterns
- Save logs to `/tmp/rnqc-session.log` for analysis
- Monitor interactive Metro client output at `/tmp/rnqc-metro.log`

### Iteration Speed Tools
- Attach to an existing RNQC Metro process for targeted debugging without restarting another project or taking over its port
- Reload the app without a full rebuild when possible
- Use the canonical runner for full-app automated qualification
- Chain targeted commands efficiently without overlapping runner-owned app, device, or Metro resources

## Key Scripts

### Canonical E2E Runner
```bash
bun run e2e:ios
bun run e2e:android
```

Run these serially from the repository root. The workspace wrappers invoke `example/test/e2e/runner.mjs`, which selects the configured platform target and owns its RNQC app, simulator or emulator, isolated Metro port, artifacts, and cleanup. Follow `docs/local-e2e.md` when signed qualification is required.

### Manual Workflow
```bash
# 1. Attach to the existing RNQC app and Metro; do not restart another project's process

# 2. Capture logs
xcrun simctl spawn booted log stream \
  --predicate 'processImagePath endswith "QuickCryptoExample"' \
  --level debug > /tmp/rnqc-session.log 2>&1 & LOG_PID=$!

# 3. Drive the relevant flow in the RNQC example app

# 4. Stop log capture and view
kill $LOG_PID
grep -E "pattern" /tmp/rnqc-session.log
```

## Common Patterns

### Rebuild & Test Cycle
```bash
# Full rebuild (TypeScript + iOS)
cd packages/react-native-quick-crypto && bun run prepare
cd ../../example && bun ios

# Then drive the affected RNQC example-app flow
```

### TypeScript-only Changes
```bash
# Rebuild TypeScript
cd packages/react-native-quick-crypto && bun run prepare

# The existing RNQC Metro process should reload the bundle; do not take over its port
```

### C++ Changes
```bash
# Requires full iOS rebuild
cd example && bun ios
```

## Log Filtering Patterns

### JavaScript Console Logs
```bash
grep -i "javascript" /tmp/rnqc-session.log
```

### Specific Debug Messages
```bash
grep -E "asymmetricKeyDetails|keyDetail|rsaImportKey" /tmp/rnqc-session.log
```

### All App Logs (with context)
```bash
tail -f /tmp/rnqc-session.log
```

## Metro Diagnostics

For interactive debugging, attach to the existing RNQC process. Never kill or restart another project's Metro or claim its port. The canonical E2E runner starts and cleans up its own isolated Metro process.

### View RNQC Metro Logs
```bash
tail -f /tmp/rnqc-metro.log
```

## Full-App Tests

Use `bun run e2e:ios` followed by `bun run e2e:android` from the repository root. Do not substitute removed Maestro flows. For narrower debugging, drive the relevant existing example-app test path and record exactly what was exercised.

## Debugging Tips

1. **Respect process ownership** - Attach for interactive work; let the canonical runner own and clean up its resources
2. **TypeScript changes** - Usually require Metro reload, not a full native rebuild
3. **C++ changes** - Require a native rebuild
4. **Log capture timing** - Start before the targeted flow and stop after the relevant output is complete
5. **Platform target** - Verify the runner or interactive session is using the intended RNQC simulator or emulator

## Files to Monitor

- `/tmp/rnqc-session.log` - iOS simulator logs
- `/tmp/rnqc-metro.log` - Interactive RNQC Metro client output
- `example/build/e2e/<platform>/<run-id>/` - Canonical runner results, screenshots, and logs
- `example/test/e2e/runner.mjs` - Canonical full-app runner

## Integration with Main Workflow

This specialist works with:
- **cpp-specialist** - For C++ debugging and OpenSSL issues
- **typescript-specialist** - For TS/JS debugging
- **crypto-specialist** - For crypto correctness verification
- **testing-specialist** - For test strategy and assertion design
