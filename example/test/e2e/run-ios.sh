#!/bin/sh

set -eu

cd "$(dirname "$0")/../.."
exec bun run e2e --platform ios "$@"
