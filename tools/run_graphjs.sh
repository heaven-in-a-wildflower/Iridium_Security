#!/usr/bin/env bash
# Run Graph.js (Docker) over all testcases and print TP/TN/FP/FN per file.
# Usage: bash run_all.sh [testcases_dir]
#
# Requirements: Docker installed and `graphjs` image built.
#   cd tools/graphjs && docker build . -t graphjs
#
# Graph.js writes results to taint_summary_detection.json.
# Empty array [] = no vulnerabilities found (clean).
# Non-empty array = detected vulnerability (with vuln_type, sink, sink_lineno).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TC_DIR="${1:-$REPO_ROOT/testcases}"
OUT_BASE="/tmp/graphjs_iridium_results"

echo "=== Graph.js (Docker) on $TC_DIR ==="
echo ""

# Remove stale results
rm -rf "$OUT_BASE"
mkdir -p "$OUT_BASE"

TP=0; TN=0; FP=0; FN=0

for jsfile in $(find "$TC_DIR" -name '*.js' | sort); do
    rel="${jsfile#$TC_DIR/}"
    gt="NEG"
    [[ "$jsfile" == */positive/* ]] && gt="POS"

    out_dir="$OUT_BASE/$(echo "$rel" | tr '/' '_')"
    mkdir -p "$out_dir"

    input_dir="$(dirname "$jsfile")"
    fname="$(basename "$jsfile")"

    # Run Graph.js — suppress SVG generation with -s
    docker run --rm \
        -v "${input_dir}":/input \
        -v "${out_dir}":/output_path \
        graphjs \
        /bin/bash -c \
        "sudo chown graphjs:graphjs -R /output_path 2>/dev/null; \
         python3 graphjs -f /input/${fname} -o /output_path -s 2>/dev/null; \
         chmod 777 -R /output_path 2>/dev/null" \
        2>/dev/null

    # Parse taint_summary_detection.json
    result_json="$out_dir/taint_summary_detection.json"
    detected=false
    vuln_types="—"
    if [[ -f "$result_json" ]]; then
        # Non-empty array means detected
        count=$(python3 -c "import json; d=json.load(open('$result_json')); print(len(d))" 2>/dev/null || echo "0")
        if [[ "$count" -gt 0 ]]; then
            detected=true
            vuln_types=$(python3 -c "
import json
d = json.load(open('$result_json'))
types = sorted(set(v.get('vuln_type','?') for v in d))
print(','.join(types))
" 2>/dev/null || echo "detected")
        fi
    fi

    if [[ "$gt" == "POS" ]]; then
        if $detected; then
            label="TP"; ((TP++)) || true
        else
            label="FN"; ((FN++)) || true
        fi
    else
        if $detected; then
            label="FP"; ((FP++)) || true
        else
            label="TN"; ((TN++)) || true
        fi
    fi

    printf "%-65s %3s  %-45s %s\n" "$rel" "$gt" "${vuln_types:0:45}" "$label"
done

echo ""
echo "=== Summary ==="
total=$((TP + TN + FP + FN))
prec=0; rec=0; f1=0
if [[ $((TP + FP)) -gt 0 ]]; then
    prec=$(python3 -c "print(f'{$TP/($TP+$FP):.2f}')")
fi
if [[ $((TP + FN)) -gt 0 ]]; then
    rec=$(python3 -c "print(f'{$TP/($TP+$FN):.2f}')")
fi
f1=$(python3 -c "
p=$prec; r=$rec
if p+r > 0: print(f'{2*p*r/(p+r):.2f}')
else: print('0.00')
")
echo "Total files : $total  (POS=$((TP+FN))  NEG=$((TN+FP)))"
echo "TP=$TP  TN=$TN  FP=$FP  FN=$FN"
echo "Precision=$prec  Recall=$rec  F1=$f1"
echo "=== Done ==="
