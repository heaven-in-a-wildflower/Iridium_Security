# Semgrep

**Maintainer:** Semgrep Inc. (open-source core)
**Version tested:** v1.154.0 (March 2026)
**Source:** https://github.com/semgrep/semgrep
**Docs:** https://semgrep.dev

## What it detects (for this testbench)

Two rulesets are used:

### 1. Built-in `p/javascript` ruleset
Includes rules for path traversal (`express-path-join-resolve-traversal`),
dynamic require (`require-request`), and a handful of other JS security issues.
Does **not** include prototype pollution rules in `p/javascript`.

### 2. Custom rules (`rules.yaml`)
Hand-written rules targeting:
- `proto-pollution-for-in` — for-in loop with `target[key] = source[key]`
- `proto-pollution-path-set` — generic dynamic property assignment
- `path-traversal-readfile` — `fs.readFile` with variable path
- `cmd-injection-template-literal` — `execSync` with template literal

## Setup

```bash
bash setup.sh    # runs: pip3 install semgrep --user
```

## Running

```bash
# Built-in rules only
bash run.sh ../../testcases

# Custom rules only
bash run_custom.sh ../../testcases

# Both combined
bash run_all.sh ../../testcases
```

## Characteristics

- **High specificity** on AFA cases — path.join traversal patterns are
  recognised but sanitised patterns (path.resolve + startsWith) are also
  flagged as FP.
- **Zero PP detection** out of the box — the `p/javascript` ruleset has no
  prototype pollution loop rule (registry rules exist but are not bundled).
- **Fast** — analyses 35 files in < 5 seconds.
- **Intra-procedural** — does not follow calls across function boundaries,
  so multi-step PP gadget chains are missed.
