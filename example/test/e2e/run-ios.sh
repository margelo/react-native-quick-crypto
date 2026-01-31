#!/bin/bash

set -e

# Start Metro
echo "Starting Metro Bundler..."
mkdir -p $HOME/output
touch $HOME/output/metro.log
bun start > $HOME/output/metro.log 2>&1 &

echo "Building and installing app to iOS Simulator..."
echo "Build logs will be written to 'ios-build.log' in uploaded artifacts"

# ios build
export RCT_USE_RN_DEP=1
export RCT_USE_PREBUILT_RNCORE=1
touch $HOME/output/ios-build.log
bun ios > $HOME/output/ios-build.log 2>&1

# Wait for build to complete and app to be installed
echo "Waiting for app to be installed..."
sleep 10

# run the e2e tests
export PATH="$PATH":"$HOME/.maestro/bin"
export MAESTRO_DRIVER_STARTUP_TIMEOUT=300000 # setting to 5 mins
export MAESTRO_CLI_NO_ANALYTICS=1
export MAESTRO_CLI_ANALYSIS_NOTIFICATION_DISABLED=true

echo "Running End-to-End tests on iOS..."

# Run maestro and capture exit code (don't exit immediately on failure)
set +e
maestro test \
  test/e2e/test-suites-flow.yml \
  --config .maestro/config.yml \
  --env PLATFORM=ios \
  --test-output-dir $HOME/output
MAESTRO_EXIT_CODE=$?
set -e

echo "Listing Output Directory"
ls -l $HOME/output/**

# Create screenshots directory and copy the latest screenshot
mkdir -p $HOME/output/screenshots
LATEST_SCREENSHOT=$(find $HOME/output -name "screenshot-*.png" -type f 2>/dev/null | sort -r | head -1)
if [ -n "$LATEST_SCREENSHOT" ]; then
  echo "Copying screenshot from $LATEST_SCREENSHOT to screenshots/ios-test-result.png"
  cp "$LATEST_SCREENSHOT" $HOME/output/screenshots/ios-test-result.png
else
  echo "No screenshot found to copy"
fi

# Exit with the original Maestro exit code
exit $MAESTRO_EXIT_CODE
