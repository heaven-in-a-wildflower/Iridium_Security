# Analysis Tools

Three open-source static analysis tools configured to run against the Iridium
Security testbench. Each tool has its own subdirectory with a setup script,
configuration, and a runner script.

## Tools

| Dir | Tool | Paper | Year | Analysis type |
|-----|------|-------|------|---------------|
| `odgen/` | ODGen | USENIX Security 2022 | 2022 | Full ODG-based inter-procedural static analysis |
| `eslint-plugin-security/` | eslint-plugin-security | — | 2026 (v4.0) | AST pattern linting |
| `semgrep/` | Semgrep (p/javascript + custom rules) | — | active | Pattern + lightweight dataflow |

## Quick start

```bash
# 1. ODGen (Python, no Docker needed)
cd tools/odgen && bash setup.sh
bash run.sh ../../testcases  # results printed to stdout

# 2. eslint-plugin-security (npm)
cd tools/eslint-plugin-security && bash setup.sh
bash run.sh ../../testcases

# 3. Semgrep (pip)
cd tools/semgrep && bash setup.sh
bash run.sh ../../testcases
```

## Evaluation results

See `results/evaluation_results.md` for the full per-file TP/TN/FP/FN table
and analysis.
