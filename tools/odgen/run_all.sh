#!/usr/bin/env bash
# Run ODGen on every testcase file and print DETECTED / NOT_DETECTED per file.
# Usage: bash run_all.sh [testcases_dir]
# Requires: setup.sh to have been run first.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ODGEN_DIR="$REPO_ROOT/artifacts/ODGen"
TC_DIR="${1:-$REPO_ROOT/testcases}"

declare -A VUL_TYPE=(
  [prototype_pollution]="proto_pollution"
  [internal_property_tampering]="ipt"
)

run_one() {
    local file="$1" type="$2" label="$3"
    local tmp="/tmp/odgen_$(basename "$file")"
    cp "$file" "$tmp"
    result=$(cd "$ODGEN_DIR" && timeout 60 python3 odgen.py "$tmp" -m -a -q -t "$type" 2>&1)
    rm -f "$tmp"
    if echo "$result" | grep -q " detected at "; then
        echo "DETECTED     $label"
    else
        echo "NOT_DETECTED $label"
    fi
}

echo "=== ODGen batch run on $TC_DIR ==="

# Prototype pollution
for f in "$TC_DIR"/prototype_pollution/positive/*.js; do
    run_one "$f" "proto_pollution" "POS $(basename "$f")"
done
for f in "$TC_DIR"/prototype_pollution/negative/*.js; do
    run_one "$f" "proto_pollution" "NEG $(basename "$f")"
done

# Internal property tampering
for f in "$TC_DIR"/internal_property_tampering/positive/*.js; do
    run_one "$f" "ipt" "POS $(basename "$f")"
done
for f in "$TC_DIR"/internal_property_tampering/negative/*.js; do
    run_one "$f" "ipt" "NEG $(basename "$f")"
done

# Arbitrary file access — path traversal
for f in "$TC_DIR"/arbitrary_file_access/positive/afa_pos_0{1,2,3,4,6}.js; do
    run_one "$f" "path_traversal" "POS $(basename "$f")"
done
for f in "$TC_DIR"/arbitrary_file_access/positive/afa_pos_05.js; do
    run_one "$f" "os_command" "POS $(basename "$f")"
done
for f in "$TC_DIR"/arbitrary_file_access/negative/*.js; do
    run_one "$f" "path_traversal" "NEG $(basename "$f")"
done

echo "=== Done ==="
