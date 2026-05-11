#!/bin/bash
# Build the Ruby gem's native extension for macOS arm64.
# Run from the repo root: ./lightspark-crypto-ruby/scripts/generate-macos-arm64.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GEM_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Installing gem dependencies..."
cd "$GEM_DIR"
bundle install

echo "Compiling native extension..."
bundle exec rake compile

echo "Done. Run 'bundle exec rspec' to test."
