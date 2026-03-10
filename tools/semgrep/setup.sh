#!/usr/bin/env bash
# Install Semgrep (pip, user-level).
set -e

echo "=== Semgrep setup ==="
pip3 install semgrep --user -q

SEMGREP="$(python3 -c 'import site; print(site.getuserbase())')/bin/semgrep"
if [ ! -f "$SEMGREP" ]; then
    SEMGREP="semgrep"
fi

echo "Semgrep version: $($SEMGREP --version 2>/dev/null || semgrep --version)"
echo "Done."
