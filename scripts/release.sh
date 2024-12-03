#!/bin/bash

echo "Starting the release process..."
echo "Provided options: $@"

echo "Publishing 'react-native-quick-crypto' to NPM"
cp README.md packages/react-native-quick-crypto/README.md
cd packages/react-native-quick-crypto
bun release $@

echo "Bumping version on example app"
cd ../../example
bun release $@

echo "Creating a Git bump commit and GitHub release"
cd ../
bun run release-it $@

echo "Successfully released QuickCrypto!"
