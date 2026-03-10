#!/usr/bin/env bash
# Install eslint + eslint-plugin-security into the repo root node_modules.
# Uses ESLint v9 flat config (eslint.config.mjs).
set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
echo "=== eslint-plugin-security setup ==="
echo "Installing into: $REPO_ROOT"

cd "$REPO_ROOT"
npm install --save-dev eslint eslint-plugin-security --legacy-peer-deps

echo ""
echo "Done. Verify with:"
echo "  node_modules/.bin/eslint --version"
