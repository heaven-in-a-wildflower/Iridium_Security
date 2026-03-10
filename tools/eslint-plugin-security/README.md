# eslint-plugin-security

**Maintainer:** eslint-community
**Version tested:** v4.0.0 (released February 2026)
**Source:** https://github.com/eslint-community/eslint-plugin-security
**Stars:** ~2,300 | used by ~38,800 projects

## What it detects

15 security rules covering:

| Rule | Targets |
|------|---------|
| `detect-object-injection` | Dynamic property write `obj[var]` — prototype pollution vector |
| `detect-non-literal-fs-filename` | `fs.readFile(var)` — path traversal |
| `detect-child-process` | `require('child_process')` — command injection |
| `detect-eval-with-expression` | `eval(expr)` — code injection |
| `detect-non-literal-require` | `require(var)` — arbitrary module load |
| `detect-unsafe-regex` | ReDoS |
| `detect-non-literal-regexp` | RegExp with variable |

## Setup

```bash
bash setup.sh    # runs: npm install eslint eslint-plugin-security
```

## Running

```bash
bash run.sh ../../testcases   # ESLint v9 flat config, JSON output
```

Configuration is in `eslint.config.mjs` (ESLint v9 flat config format).

## Characteristics

- **Very high recall** — fires on any `obj[var]` assignment, which catches
  most PP positive cases but also produces many false positives on safe
  patterns (Map, null-proto objects, allowlisted paths).
- **No inter-procedural analysis** — each file is analysed independently.
- **Runs in milliseconds** — instant feedback, good for CI pre-screening.
