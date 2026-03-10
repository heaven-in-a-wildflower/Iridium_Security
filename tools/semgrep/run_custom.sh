#!/usr/bin/env bash
# Run Semgrep with the custom rules.yaml on testcases.
# Usage: bash run_custom.sh [testcases_dir]

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TC_DIR="${1:-$REPO_ROOT/testcases}"
RULES="$REPO_ROOT/tools/semgrep/rules.yaml"
SEMGREP="${HOME}/.local/bin/semgrep"
[ -x "$SEMGREP" ] || SEMGREP="semgrep"

echo "=== Semgrep (custom rules) on $TC_DIR ==="

"$SEMGREP" --config "$RULES" "$TC_DIR" \
    --json --no-git-ignore --quiet 2>/dev/null \
| python3 << 'PYEOF'
import json, sys, glob

data = json.load(sys.stdin)
hits = {}
for r in data.get('results', []):
    rel  = r['path'].split('testcases/')[-1]
    rule = r['check_id'].split('.')[-1]
    hits.setdefault(rel, []).append(rule)

for fp in sorted(glob.glob('**/*.js', root_dir='.', recursive=True)):
    rules  = sorted(set(hits.get(fp, [])))
    fired  = ','.join(rules) if rules else '—'
    gt     = 'POS' if '/positive/' in fp else 'NEG'
    det    = bool(rules)
    result = ('TP' if det else 'FN') if gt == 'POS' else ('FP' if det else 'TN')
    print(f'{fp:<65} {gt:3} {fired[:35]:<37} {result}')
PYEOF

echo "=== Done ==="
