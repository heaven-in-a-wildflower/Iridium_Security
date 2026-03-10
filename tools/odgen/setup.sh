#!/usr/bin/env bash
# Setup ODGen (USENIX Security 2022)
# ODGen source lives in artifacts/ODGen/ (git submodule)
set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ODGEN_DIR="$REPO_ROOT/artifacts/ODGen"

echo "=== ODGen setup ==="

# 1. Initialise submodule if not already done
if [ ! -f "$ODGEN_DIR/odgen.py" ]; then
    echo "[1/2] Initialising git submodule ..."
    git -C "$REPO_ROOT" submodule update --init --recursive
else
    echo "[1/2] Submodule already initialised."
fi

# 2. Install Python + Node deps
echo "[2/2] Installing dependencies ..."
cd "$ODGEN_DIR"
bash install.sh

echo ""
echo "Done. Verify with:"
echo "  cd $ODGEN_DIR && python3 odgen_test.py"
