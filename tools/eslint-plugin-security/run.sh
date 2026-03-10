#!/usr/bin/env bash
# Run eslint-plugin-security on a directory of testcases.
# Usage: bash run.sh [testcases_dir]
# Requires: setup.sh to have been run first.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TC_DIR="${1:-$REPO_ROOT/testcases}"
CONFIG="$REPO_ROOT/tools/eslint-plugin-security/eslint.config.mjs"

echo "=== eslint-plugin-security on $TC_DIR ==="

# Run and parse JSON output
"$REPO_ROOT/node_modules/.bin/eslint" \
    --config "$CONFIG" \
    "$TC_DIR" \
    --format json 2>/dev/null | python3 - << 'PYEOF'
import json, sys

data = json.load(sys.stdin)
RULE_SHORT = {
    'security/detect-object-injection':        'obj-inject',
    'security/detect-non-literal-fs-filename': 'non-lit-fs',
    'security/detect-child-process':           'child-proc',
    'security/detect-eval-with-expression':    'eval-expr',
    'security/detect-non-literal-require':     'non-lit-req',
}
for f in sorted(data, key=lambda x: x['filePath']):
    rel  = f['filePath'].split('testcases/')[-1]
    rules = sorted({RULE_SHORT.get(m['ruleId'], m['ruleId'])
                    for m in f['messages'] if m.get('ruleId')})
    fired = ','.join(rules) if rules else '—'
    gt   = 'POS' if '/positive/' in f['filePath'] else 'NEG'
    det  = bool(rules)
    res  = ('TP' if det else 'FN') if gt == 'POS' else ('FP' if det else 'TN')
    print(f'{rel:<65} {gt:3} {fired:<35} {res}')
PYEOF

echo "=== Done ==="
