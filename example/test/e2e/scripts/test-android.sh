#!/bin/bash

set -e

OUTPUT_DIR="$HOME/output"
APK_PATH="android/app/build/outputs/apk/debug/app-debug.apk"

# Cleanup function to kill Metro on exit
cleanup() {
  echo "Cleaning up..."
  if [ -n "$METRO_PID" ] && kill -0 "$METRO_PID" 2>/dev/null; then
    echo "Stopping Metro (PID: $METRO_PID)"
    kill "$METRO_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# Verify APK exists
if [ ! -f "$APK_PATH" ]; then
  echo "Error: APK not found at $APK_PATH"
  echo "Please build the app first"
  exit 1
fi

# Start Metro
echo "Starting Metro Bundler..."
bun start > "$OUTPUT_DIR/metro.log" 2>&1 &
METRO_PID=$!

# Wait for Metro to start
echo "Waiting for Metro to start..."
for i in {1..30}; do
  if curl -sf http://localhost:8081/status > /dev/null 2>&1; then
    echo "Metro server is up!"
    break
  fi
  sleep 1
done

# Set up port forwarding so emulator can reach Metro on host
echo "Setting up adb reverse for Metro..."
adb reverse tcp:8081 tcp:8081

# Install APK to emulator
echo "Installing app to Android Emulator..."
adb install -r "$APK_PATH"

# Wait for the bundle to be ready (fetch the bundle to ensure Metro has it cached)
echo "Waiting for bundle to be ready..."
for i in {1..60}; do
  if curl -sf "http://localhost:8081/index.bundle?platform=android&dev=true&minify=false" > /dev/null 2>&1; then
    echo "Bundle is ready!"
    break
  fi
  if [ $i -eq 60 ]; then
    echo "Warning: Bundle may not be ready, continuing anyway..."
  fi
  sleep 2
done

# Note: Don't launch the app here - Maestro's launchApp command will do it.
# Launching it twice can cause Metro connection issues.

# Run E2E tests
export PATH="$PATH:$HOME/.maestro/bin"
export MAESTRO_DRIVER_STARTUP_TIMEOUT=300000
export MAESTRO_CLI_NO_ANALYTICS=1
export MAESTRO_CLI_ANALYSIS_NOTIFICATION_DISABLED=true

echo "Running End-to-End tests on Android..."
maestro test \
  test/e2e/test-suites-flow.yml \
  --config .maestro/config.yml \
  --env PLATFORM=android \
  --test-output-dir "$OUTPUT_DIR"

# Capture logcat for crash debugging
echo "Capturing logcat..."
adb logcat -d > "$OUTPUT_DIR/logcat.log" 2>&1 || true

echo "Tests completed"
