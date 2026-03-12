# Analysis Tools

Four open-source static analysis tools configured to run against the Iridium
Security testbench. Each tool targets JavaScript vulnerability detection with
a different analysis method and depth.

## Tool Summary

| Dir | Tool | Paper / Venue | Analysis type |
|-----|------|---------------|---------------|
| `eslint-plugin-security/` | eslint-plugin-security v4.0 | — (community) | AST pattern linting |
| `semgrep/` | Semgrep v1.154 + custom rules | — (active) | Pattern + shallow dataflow |
| `odgen/` | ODGen | USENIX Security 2022 | ODG-based inter-procedural taint |
| `graphjs/` | Graph.js | PLDI 2024 | Multiversion Dependency Graph taint |

---

## 1. eslint-plugin-security

**Analysis method:** AST pattern matching. Each rule fires on a syntactic
pattern (e.g., dynamic property write, non-literal `require`) with no
dataflow tracking.

**Detects:** Prototype pollution (`detect-object-injection`), path traversal
(`detect-non-literal-fs-filename`), code injection (`detect-eval-with-expression`),
arbitrary module load (`detect-non-literal-require`), ReDoS
(`detect-unsafe-regex`), child-process misuse (`detect-child-process`).

**Install:**
```bash
cd tools/eslint-plugin-security && bash setup.sh   # npm install eslint eslint-plugin-security
```

**Run:**
```bash
# Batch (all testcases)
bash run.sh ../../testcases

# Single file — invoke ESLint directly
./node_modules/.bin/eslint --no-eslintrc -c eslint.config.mjs path/to/file.js
```

**Strengths:** Runs in milliseconds; zero configuration beyond `eslint.config.mjs`;
good CI pre-screening with high recall.

**Limitations:** No inter-procedural or dataflow analysis; very high false-positive
rate on safe `obj[var]` patterns (Maps, null-proto objects, allowlisted paths).

---

## 2. Semgrep

**Analysis method:** Pattern matching with shallow, intra-procedural dataflow.
Two rulesets: the built-in `p/javascript` registry and hand-written
`rules.yaml` targeting patterns specific to this testbench.

**Detects:**
- Built-in `p/javascript`: path traversal, dynamic require, miscellaneous JS issues.
- Custom `rules.yaml`: prototype pollution (for-in loops, generic dynamic property
  assignment), path traversal (`fs.readFile` with variable), command injection
  (template-literal `execSync`).

**Install:**
```bash
cd tools/semgrep && bash setup.sh   # pip3 install semgrep --user
```

**Run:**
```bash
# Built-in rules only
bash run.sh ../../testcases

# Custom rules only
bash run_custom.sh ../../testcases

# Both combined
bash run_all.sh ../../testcases

# Single file
semgrep --config rules.yaml path/to/file.js
```

**Strengths:** Fast (35 files in < 5 s); high specificity on AFA cases;
easy to extend with custom YAML rules.

**Limitations:** Intra-procedural only — multi-step PP gadget chains across
function boundaries are missed; `p/javascript` has zero built-in PP rules.

---

## 3. ODGen

**Paper:** "Mining Node.js Vulnerabilities via Object Dependence Graph and Query"
— USENIX Security 2022 (Li, Kang, Hou, Cao — Johns Hopkins)
**Submodule location:** `artifacts/ODGen/`

**Analysis method:** Builds an Object Dependence Graph (ODG) capturing object
flow across the full program, then runs Datalog-style queries for taint paths
from user-controlled inputs to dangerous sinks. Inter-procedural.

**Detects:** Prototype pollution (`proto_pollution`), internal property tampering
(`ipt`), OS command injection (`os_command`), path traversal (`path_traversal`),
code execution (`code_exec`), XSS (`xss`).

**Install:**
```bash
cd tools/odgen && bash setup.sh   # requires Python 3.7+, Node.js 12+, npm
```

**Run:**
```bash
# Single file
bash run.sh ../../testcases/prototype_pollution/positive/pp_pos_02.js proto_pollution

# All testcases
bash run_all.sh ../../testcases
```

**Strengths:** Inter-procedural taint tracking; detects the two-hop property
access pattern (`base[k1]` then `obj[k2] = v`) that simpler tools miss.

**Limitations:** Does not model for-in key enumeration as a taint source;
does not handle destructuring assignment — these are documented blind spots
(hoisting: `pp_pos_07`, destructuring: `pp_pos_08`, `ipt_pos_05`).

---

## 4. Graph.js

**Paper:** "Efficient Static Vulnerability Analysis for JavaScript with
Multiversion Dependency Graphs" — PLDI 2024 (Ferreira et al.)
**Source:** `tools/graphjs/` (git clone of https://github.com/formalsec/graphjs)
**Runner script:** `tools/run_graphjs.sh` (NOT inside `tools/graphjs/`)

**Analysis method:** Builds a Multiversion Dependency Graph (MDG) that
coalesces the AST, control-flow graph, and data-dependency graph into one
representation, then runs graph queries (Neo4j / Cypher) for taint-style and
prototype pollution vulnerabilities. Docker-based execution.

**Detects:** Prototype pollution, path traversal, command injection, code
execution (taint-style sinks). Results written to `taint_summary_detection.json`
(empty array = clean, non-empty = vulnerability detected).

**Install:**
```bash
cd tools/graphjs && docker build . -t graphjs   # requires Docker
```

**Run:**
```bash
# Single file
docker run --rm \
  -v "$(dirname /path/to/file.js)":/input \
  -v /tmp/out:/output_path \
  graphjs \
  /bin/bash -c "python3 graphjs -f /input/file.js -o /output_path -s"

# All testcases (TP/TN/FP/FN summary)
bash tools/run_graphjs.sh testcases/
```

**Strengths:** Most sophisticated graph representation of the four tools;
inter-procedural taint with MDG captures complex multi-file dependency chains.

**Limitations:** Requires Docker and a Neo4j backend; slowest of the four tools;
some basic AFA patterns fail to detect due to graph construction gaps.

---

## Quick Start

```bash
# eslint-plugin-security
cd tools/eslint-plugin-security && bash setup.sh && bash run.sh ../../testcases

# Semgrep
cd tools/semgrep && bash setup.sh && bash run_all.sh ../../testcases

# ODGen
cd tools/odgen && bash setup.sh && bash run_all.sh ../../testcases

# Graph.js (Docker must be installed and image built first)
cd tools/graphjs && docker build . -t graphjs
bash tools/run_graphjs.sh testcases/
```

## Evaluation Results

See `results/evaluation_results.md` for the full per-file TP/TN/FP/FN table
and precision/recall analysis across all four tools.
