#!/bin/bash

set -e

# Start Metro
echo "Starting Metro Bundler..."
mkdir -p $HOME/output
touch $HOME/output/metro.log
bun start > $HOME/output/metro.log 2>&1 &

# Wait for Metro to start
echo "Waiting for Metro to start..."
sleep 15

# Install the app to emulator
echo "Building and installing app to Android Emulator..."
echo "Build logs will be written to 'android-build.log' in uploaded artifacts"
touch $HOME/output/android-build.log
bun android --active-arch-only > $HOME/output/android-build.log 2>&1

# Wait for build to complete and app to be installed
echo "Waiting for app to be installed..."
sleep 15

# Check if Metro is still running and responsive
echo "Checking Metro status..."
curl -f http://localhost:8081/status || echo "Metro not responding"

# Check if app is installed
echo "Checking if app is installed..."
adb shell pm list packages | grep com.margelo.quickcrypto.example || echo "App not found"

# run the e2e tests
export PATH="$PATH":"$HOME/.maestro/bin"
export MAESTRO_DRIVER_STARTUP_TIMEOUT=300000 # setting to 5 mins
export MAESTRO_CLI_NO_ANALYTICS=1
export MAESTRO_CLI_ANALYSIS_NOTIFICATION_DISABLED=true

echo "Running End-to-End tests on Android..."

# Run maestro and capture exit code (don't exit immediately on failure)
set +e
maestro test \
  test/e2e/test-suites-flow.yml \
  --config .maestro/config.yml \
  --env PLATFORM=android \
  --test-output-dir $HOME/output
MAESTRO_EXIT_CODE=$?
set -e

echo "Listing Output Directory"
ls -l $HOME/output/**

# Create screenshots directory and copy the latest screenshot
mkdir -p $HOME/output/screenshots
LATEST_SCREENSHOT=$(find $HOME/output -name "screenshot-*.png" -type f 2>/dev/null | sort -r | head -1)
if [ -n "$LATEST_SCREENSHOT" ]; then
  echo "Copying screenshot from $LATEST_SCREENSHOT to screenshots/android-test-result.png"
  cp "$LATEST_SCREENSHOT" $HOME/output/screenshots/android-test-result.png
else
  echo "No screenshot found to copy"
fi

# Exit with the original Maestro exit code
exit $MAESTRO_EXIT_CODE
