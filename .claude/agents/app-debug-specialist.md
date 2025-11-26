# App Debug Specialist

**Use this agent for**: React Native app debugging, log analysis, test automation, and iterative development workflows.

## Responsibilities

### Test & Debug Workflow
- Run Maestro tests and capture iOS simulator logs
- Parse and analyze console output for specific issues
- Set up automated logging with react-native-logs
- Manage Metro bundler lifecycle (start, restart, monitor)
- Coordinate test runs with log capture

### Log Management
- Capture iOS simulator logs: `xcrun simctl spawn booted log stream --predicate 'processImagePath endswith "QuickCryptoExample"' --level debug`
- Filter logs for relevant patterns
- Save logs to `/tmp/rnqc-session.log` for analysis
- Monitor Metro bundler output at `/tmp/metro.log`

### Iteration Speed Tools
- Keep Metro running in background (PID in `/tmp/metro.pid`)
- Reload app without full rebuild when possible
- Use Maestro for automated UI testing
- Chain commands efficiently (rebuild TS → rebuild iOS → run test → capture logs)

## Key Scripts

### Debug Test Runner
```bash
./scripts/debug-test.sh [test-flow] [--rebuild-ts]
```

### Manual Workflow
```bash
# 1. Ensure Metro is running
bun start > /tmp/metro.log 2>&1 & echo $! > /tmp/metro.pid

# 2. Capture logs
xcrun simctl spawn booted log stream \
  --predicate 'processImagePath endswith "QuickCryptoExample"' \
  --level debug > /tmp/rnqc-session.log 2>&1 & LOG_PID=$!

# 3. Run test
cd example && maestro test test/e2e/import-export-local.yml

# 4. Stop log capture and view
kill $LOG_PID
grep -E "pattern" /tmp/rnqc-session.log
```

## Common Patterns

### Rebuild & Test Cycle
```bash
# Full rebuild (TypeScript + iOS)
cd packages/react-native-quick-crypto && npm run prepare
cd ../../example && bun ios

# Then run debug test
./scripts/debug-test.sh
```

### TypeScript-only Changes
```bash
# Rebuild TypeScript
cd packages/react-native-quick-crypto && npm run prepare

# Metro will auto-reload, or manually restart it
pkill -P $(cat /tmp/metro.pid) && bun start & echo $! > /tmp/metro.pid
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

## Metro Management

### Check if Running
```bash
[ -f /tmp/metro.pid ] && ps -p $(cat /tmp/metro.pid) && echo "Running" || echo "Not running"
```

### Start Metro
```bash
cd example && bun start > /tmp/metro.log 2>&1 & echo $! > /tmp/metro.pid
```

### Stop Metro
```bash
kill $(cat /tmp/metro.pid) 2>/dev/null && rm /tmp/metro.pid
```

### View Metro Logs
```bash
tail -f /tmp/metro.log
```

## Maestro Tests

### Available Flows
- `test/e2e/import-export-local.yml` - Just the importKey/exportKey suite
- `test/e2e/test-suites-flow.yml` - Full test suite

### Run Specific Test
```bash
cd example && maestro test test/e2e/import-export-local.yml
```

## Debugging Tips

1. **Always keep Metro running** - Don't kill it between test runs
2. **TypeScript changes** - Require Metro reload, not full rebuild
3. **C++ changes** - Require full iOS rebuild
4. **Log capture timing** - Start before test, stop 3-5s after test completes
5. **Check PID files** - Metro and log capture PIDs in `/tmp/`

## Files to Monitor

- `/tmp/rnqc-session.log` - iOS simulator logs
- `/tmp/metro.log` - Metro bundler output
- `/tmp/metro.pid` - Metro process ID
- `example/test/e2e/*.yml` - Maestro test flows

## Integration with Main Workflow

This specialist works with:
- **cpp-specialist** - For C++ debugging and OpenSSL issues
- **typescript-specialist** - For TS/JS debugging
- **crypto-specialist** - For crypto correctness verification
- **testing-specialist** - For test strategy and assertion design
