#!/bin/bash

set -e

# Configuration
WORKSPACE="ios/QuickCryptoExample.xcworkspace"
SCHEME="QuickCryptoExample"
DERIVED_DATA_PATH="ios/build"
APP_NAME="QuickCryptoExample"
BUNDLE_ID="com.margelo.quickcrypto.example"
DEVICE_NAME="${IOS_SIMULATOR_DEVICE:-iPhone 16 Pro}"

mkdir -p $HOME/output

# Start Metro
echo "Starting Metro Bundler..."
touch $HOME/output/metro.log
bun start > $HOME/output/metro.log 2>&1 &
METRO_PID=$!

# Give Metro a moment to start
sleep 3

echo "Building iOS app with xcodebuild..."
echo "Build logs will be written to 'ios-build.log' in uploaded artifacts"
touch $HOME/output/ios-build.log

# Build the app using xcodebuild directly (much faster with ccache + DerivedData caching)
set -o pipefail
xcodebuild \
  CC=clang CPLUSPLUS=clang++ LD=clang LDPLUSPLUS=clang++ \
  -derivedDataPath "$DERIVED_DATA_PATH" \
  -workspace "$WORKSPACE" \
  -scheme "$SCHEME" \
  -sdk iphonesimulator \
  -configuration Debug \
  -destination "platform=iOS Simulator,name=$DEVICE_NAME" \
  ONLY_ACTIVE_ARCH=YES \
  CODE_SIGNING_ALLOWED=NO \
  build 2>&1 | tee $HOME/output/ios-build.log

echo "Build complete. Installing app to simulator..."

# Find the built app
APP_PATH="$DERIVED_DATA_PATH/Build/Products/Debug-iphonesimulator/$APP_NAME.app"
if [ ! -d "$APP_PATH" ]; then
  echo "Error: App not found at $APP_PATH"
  exit 1
fi

# Boot simulator if needed and install app
xcrun simctl boot "$DEVICE_NAME" 2>/dev/null || true
xcrun simctl install booted "$APP_PATH"

echo "Launching app..."
xcrun simctl launch booted "$BUNDLE_ID"

# Wait for app to be ready
echo "Waiting for app to be ready..."
sleep 5

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
ls -l $HOME/output/** || true

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
