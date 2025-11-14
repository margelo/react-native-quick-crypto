#!/bin/bash

set -e

# Start Metro
echo "Starting Metro Bundler..."
mkdir -p /tmp/e2e-output
touch /tmp/e2e-output/metro.log
bun start > /tmp/e2e-output/metro.log 2>&1 &

# Wait for Metro to start
echo "Waiting for Metro to start..."
sleep 15

# Install the app to emulator
echo "Building and installing app to Android Emulator..."
echo "Build logs will be written to 'android-build.log' in uploaded artifacts"
touch /tmp/e2e-output/android-build.log
bun android --active-arch-only > /tmp/e2e-output/android-build.log 2>&1

# Wait for build to complete and app to be installed
echo "Waiting for app to be installed..."
sleep 15

# Check if Metro is still running and responsive
echo "Checking Metro status..."
curl -f http://localhost:8081/status || echo "Metro not responding"

# Check if app is installed
echo "Checking if app is installed..."
adb shell pm list packages | grep com.quickcryptoexample || echo "App not found"

# run the e2e tests
export PATH="$PATH":"$HOME/.maestro/bin"
export MAESTRO_DRIVER_STARTUP_TIMEOUT=300000 # setting to 5 mins
export MAESTRO_CLI_NO_ANALYTICS=1
export MAESTRO_CLI_ANALYSIS_NOTIFICATION_DISABLED=true

echo "Running End-to-End tests on Android..."
maestro test \
  test/e2e/test-suites-flow.yml \
  --config .maestro/config.yml \
  --env PLATFORM=android \
  --test-output-dir /tmp/e2e-output

echo "Listing Output Directory"
ls -l /tmp/e2e-output/**
