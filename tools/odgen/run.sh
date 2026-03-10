#!/usr/bin/env bash
# Run ODGen on a single testcase file.
# Usage: bash run.sh <path/to/file.js> <vul_type>
# vul_type: proto_pollution | ipt | path_traversal | os_command | code_exec | xss
set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ODGEN_DIR="$REPO_ROOT/artifacts/ODGen"

FILE="${1:?Usage: bash run.sh <file.js> <vul_type>}"
TYPE="${2:?Usage: bash run.sh <file.js> <vul_type>}"

# ODGen can't handle paths with spaces in node subprocess calls, so copy to /tmp
TMPFILE="/tmp/odgen_target_$(basename "$FILE")"
cp "$FILE" "$TMPFILE"

cd "$ODGEN_DIR"
python3 odgen.py "$TMPFILE" -m -a -q -t "$TYPE"

rm -f "$TMPFILE"
