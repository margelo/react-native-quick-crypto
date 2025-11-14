#!/bin/bash

set -e

# Start Metro
echo "Starting Metro Bundler..."
mkdir -p /tmp/e2e-output
touch /tmp/e2e-output/metro.log
bun start > /tmp/e2e-output/metro.log 2>&1 &

echo "Building and installing app to iOS Simulator..."
echo "Build logs will be written to 'ios-build.log' in uploaded artifacts"

# ios build
export RCT_USE_RN_DEP=1
export RCT_USE_PREBUILT_RNCORE=1
touch /tmp/e2e-output/ios-build.log
bun ios > /tmp/e2e-output/ios-build.log 2>&1

# Wait for build to complete and app to be installed
echo "Waiting for app to be installed..."
sleep 10

# run the e2e tests
export PATH="$PATH":"$HOME/.maestro/bin"
export MAESTRO_DRIVER_STARTUP_TIMEOUT=300000 # setting to 5 mins
export MAESTRO_CLI_NO_ANALYTICS=1
export MAESTRO_CLI_ANALYSIS_NOTIFICATION_DISABLED=true

echo "Running End-to-End tests on iOS..."
maestro test \
  test/e2e/test-suites-flow.yml \
  --config .maestro/config.yml \
  --env PLATFORM=ios \
  --test-output-dir /tmp/e2e-output

echo "Listing Output Directory"
ls -l /tmp/e2e-output/**
