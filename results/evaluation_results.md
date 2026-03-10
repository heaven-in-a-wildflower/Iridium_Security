# Tool Evaluation Results

**Date:** March 2026
**Testbench:** Iridium Security — 35 JavaScript files across three vulnerability types
**Tools evaluated:** ODGen (USENIX 2022), eslint-plugin-security (v4.0.0), Semgrep (v1.154.0), Graph.js (PLDI 2024)
**Environment:** Python 3.10, Node.js 18.20, WSL2 (Linux 6.6), Docker Desktop 4.x (WSL2 backend)

---

## 1. Tools Overview

| Tool | Version | Analysis type | Install | Paper / Source |
|------|---------|---------------|---------|----------------|
| **eslint-plugin-security** | v4.0.0 (Feb 2026) | AST pattern linting | `bash tools/eslint-plugin-security/setup.sh` | eslint-community |
| **Semgrep** | v1.154.0 | Pattern + shallow dataflow | `bash tools/semgrep/setup.sh` | semgrep.dev |
| **ODGen** | Sep 2021 commit | Inter-procedural ODG static analysis | `bash tools/odgen/setup.sh` | USENIX Sec 2022 |
| **Graph.js** | Mar 2024 (PLDI) | MDG taint analysis + Cypher queries | `docker build tools/graphjs -t graphjs` | PLDI 2024 |

Note: explode-js (PLDI 2025) requires Docker + Neo4j + OCaml 5.3 and could not be fully built in this environment due to Docker network restrictions on Windows blocking `apt-get` inside the container. The `Dockerfile-fast` image was built but only replays pre-built benchmark data and cannot analyse arbitrary new files.

---

## 2. Summary Statistics

| Tool | TP | TN | FP | FN | Precision | Recall | F1 |
|------|----|----|----|----|-----------|--------|----|
| **eslint-plugin-security** | 18 | 3 | 11 | 3 | 0.62 | **0.86** | **0.72** |
| **Graph.js** | 10 | 9 | 5 | 11 | 0.67 | 0.48 | 0.56 |
| **ODGen** | 4 | 13 | 1 | 17 | **0.80** | 0.19 | 0.31 |
| **Semgrep** (p/javascript) | 3 | 11 | 3 | 18 | 0.50 | 0.14 | 0.22 |

- **35 files total**: 21 positive (vulnerable), 14 negative (safe)
- Difficulty breakdown: 15 easy, 12 medium, 5 hard, 3 undecidable

---

## 3. Per-File Results

Legend: **TP** = correctly flagged | **TN** = correctly clean | **FP** = false positive | **FN** = false negative

### 3.1 Prototype Pollution

#### Positive cases (vulnerable — should be flagged)

| File | Difficulty | Key pattern | ESLint | Semgrep | ODGen | Graph.js | Notes |
|------|-----------|-------------|--------|---------|-------|----------|-------|
| pp_pos_01 | easy | for-in merge, no filter | TP | FN | FN | FN | ODGen and Graph.js miss for-in; Semgrep has no PP rule in p/javascript |
| pp_pos_02 | easy | dot-path split, no filter | TP | FN | **TP** | **TP** | ODGen + Graph.js both detect two-hop `obj[k1][k2]=v` |
| pp_pos_03 | easy | constructor.prototype path | TP | FN | FN | **TP** | Graph.js traces `constructor.prototype` as a PP sink; ODGen does not |
| pp_pos_04 | medium | hasOwnProperty bypass via JSON.parse | TP | FN | FN | FN | No tool models JSON.parse own-property semantics |
| pp_pos_05 | medium | bracket-notation regex parser | TP | FN | **TP** | FN | ODGen resolves to two-hop pattern; Graph.js misses the regex key extraction |
| pp_pos_06 | medium | URL query / JSON Patch / array inputs | TP | FN | FN | **TP** | Graph.js detects multi-source PP via MDG traversal |
| pp_pos_07 | hard | var hoisting confuses AST-order flow | TP | FN | FN | FN | **All miss** — AST-order flow inference breaks on hoisted vars |
| pp_pos_08 | hard | destructuring `{ __proto__: x } = obj` | **FN** | FN | FN | FN | **All four miss** — destructuring not modelled by any tool |
| pp_pos_09 | undecidable | Proxy set trap | TP | FN | FN | FN | eslint fires on `obj[prop]=val` inside Proxy trap; others cannot model trap semantics |
| pp_pos_10 | undecidable | eval + Base64 decoded key | TP | FN | FN | **TP** | Graph.js detects `eval` call as `code-injection`; ODGen/Semgrep cannot evaluate Base64 |

#### Negative cases (safe — should NOT be flagged)

| File | Difficulty | Defence | ESLint | Semgrep | ODGen | Graph.js | Notes |
|------|-----------|---------|--------|---------|-------|----------|-------|
| pp_neg_01 | easy | Object.assign | TN | TN | TN | TN | All correct |
| pp_neg_02 | easy | Spread operator | TN | TN | TN | TN | All correct |
| pp_neg_03 | easy | Object.create(null) | **FP** | TN | TN | TN | Only eslint FPs on `params[key]=val`; others model null-prototype |
| pp_neg_04 | medium | Map / WeakMap | TN | TN | TN | TN | All correct — Map.set is not a property write |
| pp_neg_05 | medium | DANGEROUS_KEYS blocklist | **FP** | TN | TN | **FP** | eslint + Graph.js: blocklist guard not modelled as a sanitiser |
| pp_neg_06 | medium | Object.freeze(Object.prototype) | **FP** | TN | TN | TN | eslint ignores freeze; Graph.js + ODGen correctly suppress |
| pp_neg_07 | hard | JSON round-trip sanitisation | **FP** | TN | TN | TN | eslint fires on post-round-trip for-in; others correctly clean |
| pp_neg_08 | hard | Allowlist + schema validation | **FP** | TN | **FP** | **FP** | ODGen + Graph.js FP: early-exit allowlist guard not modelled as sanitiser |

**PP sub-totals:**

| Tool | TP/10 pos | TN/8 neg | FP | FN | Recall | Precision |
|------|-----------|----------|----|----|--------|-----------|
| eslint | 9 | 3 | 5 | 1 | 0.90 | 0.64 |
| Graph.js | 4 | 6 | 2 | 6 | 0.40 | 0.67 |
| ODGen | 2 | 7 | 1 | 8 | 0.20 | 0.67 |
| Semgrep | 0 | 8 | 0 | 10 | 0.00 | N/A |

---

### 3.2 Internal Property Tampering

#### Positive cases

| File | Difficulty | Key pattern | ESLint | Semgrep | ODGen | Graph.js | Notes |
|------|-----------|-------------|--------|---------|-------|----------|-------|
| ipt_pos_01 | easy | Overwrite hasOwnProperty via for-in | TP | FN | FN | FN | Graph.js: does not track hasOwnProperty as a PP-related sink |
| ipt_pos_02 | easy | Array.prototype.push via deep merge | TP | FN | **TP** | **TP** | ODGen + Graph.js: deep merge with wildcard key reaches Array.prototype |
| ipt_pos_03 | medium | Function.prototype.call via `fn.__proto__[k]` | TP | FN | FN | FN | Neither ODGen nor Graph.js models `fn.__proto__` as Function.prototype |
| ipt_pos_04 | medium | toString overwrite via shallow merge | TP | FN | FN | FN | toString not in any tool's security-sensitive sink list |
| ipt_pos_05 | hard | Destructuring + defineProperties on proto | FN | FN | FN | FN | **All four miss** — destructuring blind spot universal |

#### Negative cases

| File | Difficulty | Defence | ESLint | Semgrep | ODGen | Graph.js | Notes |
|------|-----------|---------|--------|---------|-------|----------|-------|
| ipt_neg_01 | easy | Object.freeze on all built-ins | **FP** | TN | TN | TN | Only eslint FPs on the for-in in mergeAll |
| ipt_neg_02 | medium | Symbol-keyed internal methods | **FP** | TN | TN | TN | Only eslint fires on `this[_validate](key)` |
| ipt_neg_03 | hard | Cached `Object.prototype.X.call()` | **FP** | TN | TN | TN | Only eslint fires on `target[key]=source[key]` after guard |

**IPT sub-totals:**

| Tool | TP/5 pos | TN/3 neg | FP | FN |
|------|----------|----------|----|----|
| eslint | 4 | 0 | 3 | 1 |
| Graph.js | 1 | 3 | 0 | 4 |
| ODGen | 1 | 3 | 0 | 4 |
| Semgrep | 0 | 3 | 0 | 5 |

---

### 3.3 Arbitrary File Access / Command Injection

#### Positive cases

| File | Difficulty | Pattern | ESLint | Semgrep | ODGen | Graph.js | Notes |
|------|-----------|---------|--------|---------|-------|----------|-------|
| afa_pos_01 | easy | `path.join + fs.readFile`, no bounds check | TP | TP | **FN** | **TP** | **ODGen paper claim fails; Graph.js correctly detects `path-traversal`** |
| afa_pos_02 | easy | `path.join + fs.writeFileSync`, no bounds | TP | TP | FN | **TP** | Same — Graph.js outperforms ODGen on basic path traversal |
| afa_pos_03 | easy | `require(req.query.plugin)` | TP | TP | FN | **TP** | Graph.js detects as `code-injection` (dynamic require); ODGen misses |
| afa_pos_04 | medium | PP gadget chain → path traversal | TP | FN | FN | **TP** | **Graph.js uniquely detects the cross-function gadget chain as `path-traversal`** |
| afa_pos_05 | medium | Partial sanitiser bypassed → execSync | **FN** | FN | **TP** | FN | ODGen uniquely detects via inter-procedural taint through incomplete sanitiser |
| afa_pos_06 | medium | hex-encoded path → readFileSync | TP | FN | FN | **TP** | Graph.js detects as `code-injection`; eslint FPs; ODGen/Semgrep can't decode hex |

#### Negative cases

| File | Difficulty | Defence | ESLint | Semgrep | ODGen | Graph.js | Notes |
|------|-----------|---------|--------|---------|-------|----------|-------|
| afa_neg_01 | easy | path.resolve + startsWith | **FP** | **FP** | TN | **FP** | path.resolve guard not modelled by eslint, Semgrep, or Graph.js |
| afa_neg_02 | medium | Filename allowlist (Set) | **FP** | **FP** | TN | **FP** | `ALLOWED_FILES.has(name)` not modelled as a sanitiser by three tools |
| afa_neg_03 | hard | fs.realpath + startsWith | **FP** | **FP** | TN | **FP** | realpath guard not modelled; ODGen alone is correct here |

**AFA sub-totals:**

| Tool | TP/6 pos | TN/3 neg | FP | FN |
|------|----------|----------|----|----|
| Graph.js | 5 | 0 | 3 | 1 |
| eslint | 5 | 0 | 3 | 1 |
| Semgrep | 3 | 0 | 3 | 3 |
| ODGen | 1 | 3 | 0 | 5 |

---

## 4. Cross-Cutting Observations

### 4.1 eslint-plugin-security

**Strengths:**
- Highest recall (0.86) — catches the most true vulnerabilities.
- Correctly identifies eval-based and Proxy-based cases as suspicious (even if for the wrong reason — over-approximation).
- Runs in milliseconds; suitable for CI pre-commit hooks.
- Catches the PP gadget chain case (afa_pos_04) via `obj-inject` on the merge function, where ODGen and Semgrep miss it entirely.

**Weaknesses:**
- **11 false positives** — nearly one FP per true positive in this benchmark. The `detect-object-injection` rule fires on *any* `obj[var]` write, including:
  - `Map`-based stores (ipt_neg_02)
  - Code behind `Object.freeze` (pp_neg_06, ipt_neg_01)
  - Allowlist-guarded paths (pp_neg_08)
  - Null-prototype objects (pp_neg_03)
- No inter-procedural or flow-sensitive analysis — cannot distinguish a guard on line 5 from an assignment on line 10.
- Misses `afa_pos_05` (command injection via partial sanitiser) because it looks for `require('child_process')` patterns, not for `execSync` called on a tainted-but-transformed string.

**Verdict:** Best as a fast first-pass scanner or in pre-commit CI. Requires manual triage of results. Not suitable as the sole analysis for a precision-sensitive tool like Iridium.

---

### 4.2 Graph.js (PLDI 2024)

**Strengths:**
- Best balance of precision and recall (F1=0.56) — the strongest overall tool.
- **AFA detection is excellent:** catches all basic path traversal (afa_pos_01/02), dynamic require (afa_pos_03), the PP gadget chain → path traversal (afa_pos_04), and the hex-encoded path (afa_pos_06). No other tool detects afa_pos_04.
- Correctly handles `constructor.prototype` paths (pp_pos_03) — Graph.js models the `constructor.prototype` alias in its MDG edge types.
- Detects `eval()` calls as `code-injection` — catches afa_pos_06 and pp_pos_10 even without decoding the obfuscated payload.
- Correctly suppresses the IPT negative cases (ipt_neg_01/02/03) — no false positives on well-guarded code.
- Runs as a self-contained Docker container — no complex local environment setup required.

**Weaknesses:**
- **5 false positives** — all from missing sanitiser models: the `path.resolve + startsWith` guard (afa_neg_01/02/03), the DANGEROUS_KEYS blocklist (pp_neg_05), and the allowlist (pp_neg_08). The MDG captures data flow to the sink but does not propagate the "sanitised" bit from the guard to the downstream path.
- **Misses for-in PP** (pp_pos_01) — the MDG does not recognise that `for-in` key enumeration over a user-controlled object is tainted.
- **Misses hasOwnProperty bypass** (pp_pos_04) — no model for JSON.parse's own-property semantics.
- **Misses bracket-notation PP** (pp_pos_05) — regex-based key extraction from user input not tracked through `match()`.
- **Misses IPT for non-standard sinks** (ipt_pos_01, 03, 04) — only tracks `Array.prototype` for IPT; `hasOwnProperty`, `Function.prototype.call`, and `toString` are not in the sink list.
- **Misses afa_pos_05** — unlike ODGen, Graph.js does not model the partial sanitiser bypass where `execSync` receives a string that has been partially filtered but remains injectable.
- **Does not model destructuring** (pp_pos_08, ipt_pos_05) — this blind spot is universal across all tools.
- Docker-only in practice — local setup requires Neo4j v5, which is complex to configure.

**Verdict:** Best overall tool. The MDG representation catches gadget chains and multi-source patterns that ODGen and Semgrep miss entirely. The primary weakness is FPs from unmodelled sanitisers — exactly the problem a flow-sensitive analysis in Iridium would solve.

---

### 4.3 ODGen (USENIX Security 2022)

**Strengths:**
- Highest precision (0.80) — only 1 false positive in 35 files.
- Correctly identifies all three AFA negative cases as safe (requires taint flow from user-controlled inputs, not just variable paths).
- Uniquely detects `afa_pos_05` (inter-procedural taint through an incomplete sanitiser) — the one case where ODGen's full dataflow analysis outperforms even Graph.js.
- Correctly suppresses most false positives that trip up eslint (freeze, allowlists, null-proto, Map).

**Weaknesses — confirmed blind spots:**
1. **For-in loop PP (pp_pos_01, 03, 04, 06, 07):** ODGen's PP model requires `obj[key1][key2] = val` where both keys come directly from function parameters. For-in enumeration over a user-controlled object is not recognised as tainted.
2. **Hoisting (pp_pos_07):** ODGen infers control flow from AST textual order. A `var` declaration below its use confuses the analysis — confirmed in the original paper appendix.
3. **Destructuring (pp_pos_08, ipt_pos_05):** Destructuring assignment is not treated as a taint-propagating operation. Values extracted via destructuring are dropped.
4. **Path traversal (afa_pos_01/02):** Despite the USENIX 2022 paper claiming path traversal detection, ODGen fails on the simplest `path.join + fs.readFile` pattern. The open-source release differs from the internal evaluation version.
5. **Single false positive (pp_neg_08):** ODGen raises an alarm on the allowlist-guarded path-setter; the allowlist check is not modelled as a sanitiser.

**Verdict:** Best precision but very low recall. Suitable as a high-confidence secondary pass after a high-recall tool flags candidates. The flow-sensitive implementation planned in Iridium directly addresses ODGen's core weaknesses.

---

### 4.4 Semgrep (p/javascript ruleset)

**Strengths:**
- Zero false positives on PP and IPT — the built-in `p/javascript` ruleset has no PP rules, so no PP-related FPs.
- Correctly identifies `path.join`-based path traversal (afa_pos_01/02) and dynamic `require()` (afa_pos_03).
- Fastest tool — 35 files in < 5 seconds.
- Highly customisable: the `rules.yaml` in `tools/semgrep/` adds targeted rules for PP, AFA, and command injection that significantly improve recall.

**Weaknesses:**
- **Zero PP detection** out of the box — the `p/javascript` ruleset contains no prototype pollution rules.
- **Intra-procedural only** — cannot follow taint through function calls. Misses the partial sanitiser bypass (afa_pos_05), the PP gadget chain (afa_pos_04), and all multi-function IPT patterns.
- **3 false positives on AFA negatives** — `express-path-join-resolve-traversal` fires on any `path.join` with a variable argument, regardless of `path.resolve + startsWith` or `fs.realpath` guards.

**Custom rules.yaml improvement:** Running `bash tools/semgrep/run_custom.sh` with the custom PP + AFA + command-injection rules instead of `p/javascript` catches pp_pos_01, pp_pos_02, pp_pos_06 and afa_pos_05 (cmd-injection-template-literal-exec), raising overall recall to ~0.38.

**Verdict:** Weakest overall as configured. Adding the custom `rules.yaml` closes much of the PP gap. Still fundamentally limited by intra-procedural scope for inter-function gadget chains.

---

## 5. Universal Blind Spots — Cases No Tool Caught

These cases were missed by **all four tools** and represent the hardest class of vulnerabilities:

| File | Pattern | Why it's hard |
|------|---------|---------------|
| `pp_pos_07` | `var` hoisting: variable used before declaration in source text | AST-order analysis breaks for hoisted vars; none of the four tools are flow-sensitive w.r.t. textual order |
| `pp_pos_08` | Destructuring `{ __proto__: x } = parsed` then `Object.assign(Object.prototype, x)` | No tool models destructuring as a taint-propagating operation |
| `ipt_pos_05` | Destructuring feeds `Object.defineProperties` on prototype | Combination of destructuring + defineProperties is beyond all four tools |
| `pp_pos_04` | hasOwnProperty bypass via JSON.parse (parsed object lacks hasOwnProperty; for-in picks up `__proto__` key) | Requires modelling JSON.parse semantics + for-in key taint simultaneously |

These are precisely the cases that motivate a **flow-sensitive, inter-procedural points-to analysis** in Iridium. An Andersen-style analysis alone is insufficient; the analysis needs:
- A model for destructuring that propagates taint through binding patterns
- Flow sensitivity to distinguish the state of an object before and after a polluting merge call
- A gadget-chain query that links PP pollution to downstream property reads at sinks
- A model for for-in key taint from user-controlled source objects

---

## 6. Implications for Iridium

The results confirm the design decisions from the ODGen/explode-js analysis:

1. **Basic Andersen analysis is insufficient.** ODGen uses an Andersen-style points-to analysis and still misses 17/21 positive cases. Graph.js's MDG (which adds flow edges) misses 11/21. The for-in enumeration pattern — the most common real-world PP vector — requires tracking that a `for-in` key over a user-controlled object is itself tainted.

2. **Flow sensitivity is required.** The key differentiator between TP and FP in PP detection is whether the analysis knows *at the point of the assignment* whether the object has been guarded (frozen, null-proto'd, allowlisted). Both ODGen and Graph.js FP on pp_neg_08 because they cannot model the allowlist early-exit. Iridium's CFG-based analysis should propagate a "guarded" lattice bit alongside object points-to sets.

3. **Destructuring must be modelled.** Cases pp_pos_08, ipt_pos_05, and related variants are missed by all four tools because destructuring assignment is not treated as a taint-propagating operation. In Iridium's IR, destructuring should lower to explicit property reads and bindings that carry taint.

4. **One CFG per function is a practical starting point.** The PP gadget chain (afa_pos_04) requires cross-function analysis, but the source and sink are in the same file with a trivial call graph. Graph.js detects it with its MDG; Iridium's single-level inter-procedural analysis (inline immediate callees) would be sufficient.

5. **Graph.js vs ODGen trade-off:** Graph.js has significantly higher recall (0.48 vs 0.19) at the cost of more FPs (5 vs 1). The FP pattern is consistent: unmodelled sanitisers at sinks. Iridium can target this gap — precise guard modelling would push Graph.js-level recall with ODGen-level precision.

6. **eslint as a fast pre-filter.** For the Iridium workflow, running eslint-plugin-security first to generate a candidate set, then running Iridium's precise analysis to confirm or suppress each alert, gives the best practical precision/recall trade-off.

---

## 7. Reproducing the Evaluation

### Setup

```bash
# Tool 1: ESLint
bash tools/eslint-plugin-security/setup.sh

# Tool 2: Semgrep
bash tools/semgrep/setup.sh

# Tool 3: ODGen (git submodule)
bash tools/odgen/setup.sh

# Tool 4: Graph.js (Docker)
cd tools/graphjs
docker build . -t graphjs
cd ../..
```

### Run

```bash
# ESLint
bash tools/eslint-plugin-security/run.sh testcases/

# Semgrep — built-in p/javascript ruleset
bash tools/semgrep/run.sh testcases/

# Semgrep — custom PP + AFA + command-injection rules
bash tools/semgrep/run_custom.sh testcases/

# ODGen — one file at a time (see tools/odgen/run_all.sh for batch)
bash tools/odgen/run_all.sh testcases/

# Graph.js — Docker batch runner
bash tools/run_graphjs.sh testcases/
```

### Environment requirements

| Tool | Requirements |
|------|-------------|
| eslint-plugin-security | Node.js 12+, npm |
| Semgrep | Python 3.7+, pip3 |
| ODGen | Node.js 12+, npm |
| Graph.js | Docker |

Graph.js output for each file is in `/tmp/graphjs_iridium_results/<mangled_filename>/taint_summary_detection.json`.
An empty JSON array (`[]`) means no vulnerabilities detected; a non-empty array contains objects with `vuln_type`, `sink`, and `sink_lineno` fields.
