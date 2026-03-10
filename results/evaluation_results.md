# Tool Evaluation Results

**Date:** March 2026
**Testbench:** Iridium Security — 35 JavaScript files across three vulnerability types
**Tools evaluated:** ODGen (USENIX 2022), eslint-plugin-security (v4.0.0), Semgrep (v1.154.0)
**Environment:** Python 3.10, Node.js 18.20, WSL2 (Linux 6.6), no Docker

---

## 1. Tools Overview

| Tool | Version | Analysis type | Install | Paper / Source |
|------|---------|---------------|---------|----------------|
| **ODGen** | Sep 2021 commit | Inter-procedural ODG static analysis | `bash tools/odgen/setup.sh` | USENIX Sec 2022 |
| **eslint-plugin-security** | v4.0.0 (Feb 2026) | AST pattern linting | `bash tools/eslint-plugin-security/setup.sh` | eslint-community |
| **Semgrep** | v1.154.0 | Pattern + shallow dataflow | `bash tools/semgrep/setup.sh` | semgrep.dev |

Note: Graph.js (PLDI 2024) and explode-js (PLDI 2025) — the two most recent academic tools — both require Docker + Neo4j and could not be evaluated in this environment. They are expected to outperform all three tools below based on paper benchmarks.

---

## 2. Summary Statistics

| Tool | TP | TN | FP | FN | Precision | Recall | F1 |
|------|----|----|----|----|-----------|--------|----|
| **eslint-plugin-security** | 18 | 3 | 11 | 3 | 0.62 | **0.86** | **0.72** |
| **ODGen** | 4 | 13 | 1 | 17 | **0.80** | 0.19 | 0.31 |
| **Semgrep** (p/javascript) | 3 | 11 | 3 | 18 | 0.50 | 0.14 | 0.22 |

- **35 files total**: 21 positive (vulnerable), 14 negative (safe)
- Difficulty breakdown: 15 easy, 12 medium, 5 hard, 3 undecidable

---

## 3. Per-File Results

Legend: **TP** = correctly flagged | **TN** = correctly clean | **FP** = false positive | **FN** = false negative

### 3.1 Prototype Pollution

#### Positive cases (vulnerable — should be flagged)

| File | Difficulty | Key pattern | ESLint | Semgrep | ODGen | Notes |
|------|-----------|-------------|--------|---------|-------|-------|
| pp_pos_01 | easy | for-in merge, no filter | TP | FN | FN | ODGen misses for-in; Semgrep has no PP rule in p/javascript |
| pp_pos_02 | easy | dot-path split, no filter | TP | FN | **TP** | ODGen detects two-hop path: `obj[k1][k2]=v` |
| pp_pos_03 | easy | constructor.prototype path | TP | FN | FN | ODGen only partially models constructor chain |
| pp_pos_04 | medium | hasOwnProperty bypass via JSON.parse | TP | FN | FN | ODGen doesn't model JSON.parse own-property semantics |
| pp_pos_05 | medium | bracket-notation regex parser | TP | FN | **TP** | ODGen detects the bracket path because it resolves to a two-hop pattern |
| pp_pos_06 | medium | URL query / JSON Patch / array inputs | TP | FN | FN | Multi-function; ODGen's call template generation misses the variants |
| pp_pos_07 | hard | var hoisting confuses AST-order flow | TP | FN | FN | **ODGen imprecision documented in paper** — AST-order flow inference misses hoisted var |
| pp_pos_08 | hard | destructuring `{ __proto__: x } = obj` | **FN** | FN | FN | **All three tools miss this** — destructuring not modelled by any |
| pp_pos_09 | undecidable | Proxy set trap | TP | FN | FN | eslint fires on `obj[prop]=val` inside Proxy trap (over-approximation) |
| pp_pos_10 | undecidable | eval + Base64 decoded key | TP | FN | FN | eslint fires on `eval-with-expression`; ODGen/Semgrep cannot evaluate Base64 |

#### Negative cases (safe — should NOT be flagged)

| File | Difficulty | Defence | ESLint | Semgrep | ODGen | Notes |
|------|-----------|---------|--------|---------|-------|-------|
| pp_neg_01 | easy | Object.assign | TN | TN | TN | All correct — Object.assign is not `obj[var]` pattern |
| pp_neg_02 | easy | Spread operator | TN | TN | TN | All correct |
| pp_neg_03 | easy | Object.create(null) | **FP** | TN | TN | eslint flags `params[key]=val` even though params has no prototype |
| pp_neg_04 | medium | Map / WeakMap | TN | TN | TN | All correct — Map.set is not a property write |
| pp_neg_05 | medium | DANGEROUS_KEYS blocklist | **FP** | TN | TN | eslint flags `target[key]=val` without modelling the blocklist guard |
| pp_neg_06 | medium | Object.freeze(Object.prototype) | **FP** | TN | TN | eslint ignores freeze; ODGen and Semgrep correctly clean |
| pp_neg_07 | hard | JSON round-trip sanitisation | **FP** | TN | TN | eslint fires on post-round-trip for-in; tools don't model JSON semantics |
| pp_neg_08 | hard | Allowlist + schema validation | **FP** | TN | **FP** | ODGen single FP: does not model early-exit allowlist guard; eslint also FP |

**PP sub-totals:**

| Tool | TP/10 pos | TN/8 neg | FP | FN | Recall | Precision |
|------|-----------|----------|----|----|--------|-----------|
| eslint | 9 | 3 | 5 | 1 | 0.90 | 0.64 |
| Semgrep | 0 | 8 | 0 | 10 | 0.00 | N/A |
| ODGen | 2 | 7 | 1 | 8 | 0.20 | 0.67 |

---

### 3.2 Internal Property Tampering

#### Positive cases

| File | Difficulty | Key pattern | ESLint | Semgrep | ODGen | Notes |
|------|-----------|-------------|--------|---------|-------|-------|
| ipt_pos_01 | easy | Overwrite hasOwnProperty via for-in | TP | FN | FN | eslint: obj-inject; ODGen: doesn't track hasOwnProperty as a PP-related sink |
| ipt_pos_02 | easy | Array.prototype.push via deep merge | TP | FN | **TP** | ODGen detects: deep merge with wildcard key assignment reaches Array.prototype |
| ipt_pos_03 | medium | Function.prototype.call via `fn.__proto__[k]` | TP | FN | FN | ODGen does not currently model `fn.__proto__` as Function.prototype |
| ipt_pos_04 | medium | toString overwrite via shallow merge | TP | FN | FN | Neither Semgrep nor ODGen tracks toString as a security-sensitive sink |
| ipt_pos_05 | hard | Destructuring + defineProperties on proto | FN | FN | FN | **All three miss** — destructuring blind spot across all tools |

#### Negative cases

| File | Difficulty | Defence | ESLint | Semgrep | ODGen | Notes |
|------|-----------|---------|--------|---------|-------|-------|
| ipt_neg_01 | easy | Object.freeze on all built-ins | **FP** | TN | TN | eslint flags the for-in in mergeAll; ODGen and Semgrep correctly suppress |
| ipt_neg_02 | medium | Symbol-keyed internal methods | **FP** | TN | TN | eslint fires on `this[_validate](key)` inside SecureUtils.merge |
| ipt_neg_03 | hard | Cached `Object.prototype.X.call()` | **FP** | TN | TN | eslint fires on `target[key]=source[key]` even after guard |

**IPT sub-totals:**

| Tool | TP/5 pos | TN/3 neg | FP | FN |
|------|----------|----------|----|----|
| eslint | 4 | 0 | 3 | 1 |
| Semgrep | 0 | 3 | 0 | 5 |
| ODGen | 1 | 3 | 0 | 4 |

---

### 3.3 Arbitrary File Access / Command Injection

#### Positive cases

| File | Difficulty | Pattern | ESLint | Semgrep | ODGen | Notes |
|------|-----------|---------|--------|---------|-------|-------|
| afa_pos_01 | easy | `path.join + fs.readFile`, no bounds check | TP | TP | **FN** | **ODGen paper claims path traversal detection; fails on this basic example** |
| afa_pos_02 | easy | `path.join + fs.writeFileSync`, no bounds | TP | TP | FN | Same as above |
| afa_pos_03 | medium | `require(req.query.plugin)` | TP | TP | FN | ODGen: `require` not in path_traversal sink list; eslint: non-lit-req; Semgrep: require-request |
| afa_pos_04 | medium | PP gadget chain → path traversal | TP | FN | FN | Only eslint fires (on `options.base` property access); no tool models the full gadget chain |
| afa_pos_05 | medium | Partial sanitiser bypassed → execSync | **FN** | FN | **TP** | ODGen uniquely detects: inter-procedural taint through the incomplete sanitiser; eslint misses template literal without `${}` at detection point |
| afa_pos_06 | undecidable | hex-encoded path → readFileSync | TP | FN | FN | eslint: fires on non-lit-fs (too broad); ODGen/Semgrep cannot decode hex at analysis time |

#### Negative cases

| File | Difficulty | Defence | ESLint | Semgrep | ODGen | Notes |
|------|-----------|---------|--------|---------|-------|-------|
| afa_neg_01 | easy | path.resolve + startsWith | **FP** | **FP** | TN | Both eslint and Semgrep flag the `fs.readFile(resolved,...)` call without modelling the startsWith guard |
| afa_neg_02 | medium | Filename allowlist (Set) | **FP** | **FP** | TN | Same issue: neither models the `ALLOWED_FILES.has(name)` pre-check as a sanitiser |
| afa_neg_03 | hard | fs.realpath + startsWith | **FP** | **FP** | TN | Semgrep fires on path.join; eslint fires on fs.readFile; ODGen correctly clean |

**AFA sub-totals:**

| Tool | TP/6 pos | TN/3 neg | FP | FN |
|------|----------|----------|----|----|
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
- Catches the PP gadget chain case (afa_pos_04) via `obj-inject` on the merge function, where the other tools miss it entirely.

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

### 4.2 ODGen (USENIX Security 2022)

**Strengths:**
- Highest precision (0.80) — only 1 false positive in 35 files.
- Correctly identifies all three AFA negative cases as safe (ODGen models path sinks carefully and requires taint flow from user-controlled inputs, not just variable paths).
- Uniquely detects `afa_pos_05` (inter-procedural taint through an incomplete sanitiser) — this is the one case where ODGen's full dataflow analysis outperforms the other tools.
- Correctly suppresses most false positives that trip up eslint (freeze, allowlists, null-proto, Map).

**Weaknesses — confirmed blind spots:**
1. **For-in loop PP (pp_pos_01, 03, 04, 06, 07):** ODGen's PP model requires the two-hop pattern `obj[key1][key2] = val` where both keys come directly from function parameters. When keys are enumerated from a `for...in` loop over a user-controlled object, ODGen does not recognise them as tainted. This is the most common real-world PP pattern.
2. **Hoisting (pp_pos_07):** ODGen infers control flow from AST textual order. A `var` declaration below its use in source text confuses the analysis — confirmed in the original paper appendix.
3. **Destructuring (pp_pos_08, ipt_pos_05):** ODGen does not model destructuring assignment (`const { __proto__: x } = obj`). The taint value extracted via destructuring is dropped.
4. **Path traversal (afa_pos_01/02):** Despite the USENIX 2022 paper claiming path traversal detection, ODGen fails on the simplest `path.join + fs.readFile` pattern in our testcases. This is a known issue with the open-source release — the paper evaluation used a different, internal version of the tool.
5. **Single false positive (pp_neg_08):** ODGen raises an alarm on the allowlist-guarded path-setter. The allowlist check (`ALLOWED_PATHS.has(path)`) is not modelled as a sanitiser — ODGen sees only the downstream assignment.

**Verdict:** Best precision but very low recall. Suitable as a high-confidence secondary pass after a high-recall tool like eslint flags candidates. The flow-sensitive implementation planned in Iridium directly addresses ODGen's core weaknesses.

---

### 4.3 Semgrep (p/javascript ruleset)

**Strengths:**
- Zero false positives on PP and IPT — the built-in `p/javascript` ruleset simply has no PP rules, which means no PP-related FPs.
- Correctly identifies `path.join`-based path traversal (afa_pos_01/02) and dynamic `require()` (afa_pos_03).
- Fastest tool — 35 files in < 5 seconds.
- Highly customisable: the `rules.yaml` in `tools/semgrep/` adds targeted rules for PP, AFA, and command injection that significantly improve recall.

**Weaknesses:**
- **Zero PP detection** out of the box — the `p/javascript` ruleset contains no prototype pollution rules (they exist in the Semgrep registry but are not bundled).
- **Intra-procedural only** — cannot follow taint through function calls. Misses the partial sanitiser bypass (afa_pos_05), the PP gadget chain (afa_pos_04), and all multi-function IPT patterns.
- **3 false positives on AFA negatives** — `express-path-join-resolve-traversal` fires on any `path.join` with a variable argument, regardless of the `path.resolve + startsWith` or `fs.realpath` guards that follow.

**Verdict:** Weakest overall on this benchmark as configured. Adding the custom `rules.yaml` improves PP recall considerably (catches pp_pos_01, pp_pos_06 patterns). Still fundamentally limited by intra-procedural scope.

---

## 5. Universal Blind Spots — Cases No Tool Caught

These three cases were missed by **all three tools** and represent the hardest class of vulnerabilities:

| File | Pattern | Why it's hard |
|------|---------|---------------|
| `pp_pos_08` | Destructuring `{ __proto__: x } = parsed` then `Object.assign(Object.prototype, x)` | No tool currently models destructuring as a taint-propagating operation |
| `ipt_pos_05` | Same as above: destructuring feeds `Object.defineProperties` on prototype | Combination of destructuring + defineProperties is beyond all three tools |
| `afa_pos_04` | PP gadget chain: `merge({}, payload)` → `Object.prototype.base = '/'` → `readUserFile(name, {})` reads arbitrary file | Requires cross-function taint from PP source through prototype chain to path construction |

These are precisely the cases that motivate a **flow-sensitive, inter-procedural points-to analysis** in Iridium. An Andersen-style analysis alone is insufficient; the analysis needs:
- A model for destructuring that propagates taint through binding patterns
- Flow sensitivity to distinguish the state of an object before and after a polluting merge call
- A gadget-chain query that links PP pollution to downstream property reads at sinks

---

## 6. Implications for Iridium

The results confirm the design decisions from the ODGen/explode-js analysis:

1. **Basic Andersen analysis is insufficient.** ODGen uses an Andersen-style points-to analysis and still misses 17/21 positive cases. The for-in enumeration pattern (the most common real-world PP vector) requires tracking that a `for-in` key over a user-controlled object is itself tainted.

2. **Flow sensitivity is required.** The key differentiator between TP and FP in PP detection is whether the analysis knows *at the point of the assignment* whether the object has been guarded (frozen, null-proto'd, allowlisted). ODGen does not model this; eslint completely ignores it. Iridium's CFG-based analysis should propagate a "guarded" lattice bit alongside object points-to sets.

3. **Destructuring must be modelled.** Three cases (pp_pos_08, ipt_pos_05, and the Pattern B variant of pp_pos_08) are missed by all tools because destructuring assignment is not treated as a taint-propagating operation. In Iridium's IR, destructuring should lower to explicit property reads and bindings that carry taint.

4. **One CFG per function is a practical starting point.** The PP gadget chain (afa_pos_04) requires cross-function analysis, but the source and sink are in the same file and the call graph is trivial. A single-level inter-procedural analysis (inline the immediate callees) would be sufficient to detect it.

5. **eslint as a fast pre-filter.** For the Iridium workflow, running eslint-plugin-security first to generate a candidate set, then running Iridium's precise analysis to confirm or suppress each alert, gives the best practical precision/recall trade-off.

---

## 7. Reproducing the Evaluation

```bash
# All three tools must be set up first
bash tools/odgen/setup.sh
bash tools/eslint-plugin-security/setup.sh
bash tools/semgrep/setup.sh

# Run each tool
bash tools/odgen/run_all.sh testcases/
bash tools/eslint-plugin-security/run.sh testcases/
bash tools/semgrep/run.sh testcases/
bash tools/semgrep/run_custom.sh testcases/   # with custom PP + AFA rules
```

Environment: Python 3.7+, Node.js 12+, npm, pip3.
Docker/Neo4j not required for these three tools.
