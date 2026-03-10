#!/usr/bin/env bash
# Run Semgrep built-in p/javascript rules on testcases.
# Usage: bash run.sh [testcases_dir]

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TC_DIR="${1:-$REPO_ROOT/testcases}"
SEMGREP="${HOME}/.local/bin/semgrep"
[ -x "$SEMGREP" ] || SEMGREP="semgrep"

echo "=== Semgrep (p/javascript) on $TC_DIR ==="

"$SEMGREP" --config "p/javascript" "$TC_DIR" \
    --json --no-git-ignore --quiet 2>/dev/null \
| python3 << 'PYEOF'
import json, sys, glob

data   = json.load(sys.stdin)
hits   = {}
for r in data.get('results', []):
    rel  = r['path'].split('testcases/')[-1]
    rule = r['check_id'].split('.')[-1]
    hits.setdefault(rel, []).append(rule)

base = sys.argv[1] if len(sys.argv) > 1 else '.'
for fp in sorted(glob.glob('**/*.js', root_dir=base, recursive=True)):
    rules  = sorted(set(hits.get(fp, [])))
    fired  = ','.join(rules) if rules else '—'
    gt     = 'POS' if '/positive/' in fp else 'NEG'
    det    = bool(rules)
    result = ('TP' if det else 'FN') if gt == 'POS' else ('FP' if det else 'TN')
    print(f'{fp:<65} {gt:3} {fired[:35]:<37} {result}')
PYEOF

echo "=== Done ==="
