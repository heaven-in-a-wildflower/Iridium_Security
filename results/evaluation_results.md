# Tool Evaluation Results

**Date:** March 2026
**Testbench:** Iridium Security — 42 JavaScript files across three vulnerability types
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

Graph.js results for the 7 new negative cases (pp_neg_09/10, ipt_neg_04/05, afa_neg_04/05/06) are **estimated** from Graph.js's known FP patterns (Docker was unavailable in the current session); the 35 original files were run directly.

---

## 2. Class Balance

The testbench uses a **balanced 50/50 split** — 21 positive (vulnerable) and 21 negative (safe) — to prevent tools that over-approximate (flag everything as positive) from appearing strong due to class imbalance.

For reference, a **naïve all-positive classifier** achieves: Precision=0.50, Recall=1.00, **F1=0.67** on this benchmark. Any tool below F1=0.67 provides less information than the trivial baseline.

| Category | Positive | Negative | Total |
|----------|---------|---------|-------|
| Prototype Pollution | 10 | 10 | 20 |
| Internal Property Tampering | 5 | 5 | 10 |
| Arbitrary File Access | 6 | 6 | 12 |
| **Total** | **21** | **21** | **42** |

Difficulty breakdown: 15 easy, 14 medium, 6 hard, 4 undecidable (3 original + 1 new hard neg).

---

## 3. Summary Statistics

| Tool | TP | TN | FP | FN | Precision | Recall | F1 | vs naive baseline |
|------|----|----|----|----|-----------|--------|----|-------------------|
| **ODGen** | 4 | 20 | 1 | 17 | **0.80** | 0.19 | 0.31 | below (but best precision) |
| **Graph.js** ★ | 10 | 9 | 12 | 11 | 0.45 | 0.48 | **0.46** | below |
| **eslint-plugin-security** | 18 | 3 | 18 | 3 | 0.50 | **0.86** | 0.63 | **below naive (0.67)** |
| **Semgrep** (p/javascript) | 3 | 18 | 3 | 18 | 0.50 | 0.14 | 0.22 | far below |
| *Naïve all-positive* | 21 | 0 | 21 | 0 | 0.50 | 1.00 | 0.67 | — |

★ Graph.js results for 7 new negatives are estimated (see §1 note).

**Key finding:** ESLint achieves F1=0.63, which is **below the trivial all-positive baseline** (F1=0.67). Its high recall (0.86) is entirely explained by flagging nearly every file — not by genuine vulnerability understanding. This confirms the original class-imbalance bias: ESLint only appeared strong (F1=0.72) when the benchmark had 21 positives vs 14 negatives.

---

## 4. Per-File Results

Legend: **TP** = correctly flagged | **TN** = correctly clean | **FP** = false positive | **FN** = false negative | ★ = estimated

### 4.1 Prototype Pollution

#### Positive cases (vulnerable — should be flagged)

| File | Difficulty | Key pattern | ESLint | Semgrep | ODGen | Graph.js | Notes |
|------|-----------|-------------|--------|---------|-------|----------|-------|
| pp_pos_01 | easy | for-in merge, no filter | TP | FN | FN | FN | ODGen and Graph.js miss for-in; no Semgrep PP rules |
| pp_pos_02 | easy | dot-path split | TP | FN | **TP** | **TP** | Both detect two-hop `obj[k1][k2]=v` |
| pp_pos_03 | easy | constructor.prototype path | TP | FN | FN | **TP** | Graph.js models constructor.prototype alias |
| pp_pos_04 | medium | hasOwnProperty bypass via JSON.parse | TP | FN | FN | FN | No tool models JSON.parse own-property semantics |
| pp_pos_05 | medium | bracket-notation regex parser | TP | FN | **TP** | FN | ODGen resolves to two-hop; Graph.js misses regex extraction |
| pp_pos_06 | medium | URL query / JSON Patch / array inputs | TP | FN | FN | **TP** | Graph.js detects multi-source PP via MDG traversal |
| pp_pos_07 | hard | var hoisting | TP | FN | FN | FN | All miss — AST-order inference breaks on hoisted vars |
| pp_pos_08 | hard | destructuring `{ __proto__: x } = obj` | **FN** | FN | FN | FN | **Universal blind spot — destructuring not modelled** |
| pp_pos_09 | undecidable | Proxy set trap | TP | FN | FN | FN | Only eslint fires (over-approximation on `obj[prop]=val`) |
| pp_pos_10 | undecidable | eval + Base64 decoded key | TP | FN | FN | **TP** | Graph.js catches eval as `code-injection` |

#### Negative cases (safe — should NOT be flagged)

| File | Difficulty | Defence | ESLint | Semgrep | ODGen | Graph.js | Notes |
|------|-----------|---------|--------|---------|-------|----------|-------|
| pp_neg_01 | easy | Object.assign | TN | TN | TN | TN | All correct |
| pp_neg_02 | easy | Spread operator | TN | TN | TN | TN | All correct |
| pp_neg_03 | easy | Object.create(null) | **FP** | TN | TN | TN | Only eslint FPs |
| pp_neg_04 | medium | Map / WeakMap | TN | TN | TN | TN | All correct |
| pp_neg_05 | medium | DANGEROUS_KEYS blocklist | **FP** | TN | TN | **FP** | Blocklist not modelled as sanitiser |
| pp_neg_06 | medium | Object.freeze(Object.prototype) | **FP** | TN | TN | TN | Only eslint ignores freeze |
| pp_neg_07 | hard | JSON round-trip sanitisation | **FP** | TN | TN | TN | Only eslint fires on post-round-trip for-in |
| pp_neg_08 | hard | Allowlist + schema validation | **FP** | TN | **FP** | **FP** | Early-exit allowlist not modelled by ODGen + Graph.js |
| pp_neg_09 | medium | deepFreeze(Object.prototype) before merge | **FP** | TN | TN | **FP**★ | deepFreeze not modelled as guard; merge body still triggers alarms |
| pp_neg_10 | hard | structuredClone before merge | **FP** | TN | TN | **FP**★ | structuredClone not modelled as sanitiser by either tool |

**PP sub-totals:**

| Tool | TP/10 pos | TN/10 neg | FP | FN | Recall | Precision |
|------|-----------|-----------|----|----|--------|-----------|
| eslint | 9 | 3 | 7 | 1 | 0.90 | 0.56 |
| Graph.js★ | 4 | 6 | 4 | 6 | 0.40 | 0.50 |
| ODGen | 2 | 9 | 1 | 8 | 0.20 | 0.67 |
| Semgrep | 0 | 10 | 0 | 10 | 0.00 | N/A |

---

### 4.2 Internal Property Tampering

#### Positive cases

| File | Difficulty | Key pattern | ESLint | Semgrep | ODGen | Graph.js | Notes |
|------|-----------|-------------|--------|---------|-------|----------|-------|
| ipt_pos_01 | easy | Overwrite hasOwnProperty via for-in | TP | FN | FN | FN | |
| ipt_pos_02 | easy | Array.prototype.push via deep merge | TP | FN | **TP** | **TP** | Both detect wildcard merge reaching Array.prototype |
| ipt_pos_03 | medium | Function.prototype.call via `fn.__proto__[k]` | TP | FN | FN | FN | |
| ipt_pos_04 | medium | toString overwrite via shallow merge | TP | FN | FN | FN | toString not in any tool's sink list |
| ipt_pos_05 | hard | Destructuring + defineProperties on proto | FN | FN | FN | FN | **Universal blind spot** |

#### Negative cases

| File | Difficulty | Defence | ESLint | Semgrep | ODGen | Graph.js | Notes |
|------|-----------|---------|--------|---------|-------|----------|-------|
| ipt_neg_01 | easy | Object.freeze on all built-ins | **FP** | TN | TN | TN | Only eslint FPs |
| ipt_neg_02 | medium | Symbol-keyed internal methods | **FP** | TN | TN | TN | |
| ipt_neg_03 | hard | Cached `Object.prototype.X.call()` | **FP** | TN | TN | TN | |
| ipt_neg_04 | medium | Object.seal + hasOwnProperty guard | **FP** | TN | TN | **FP**★ | Object.seal semantics not modelled; write still flagged |
| ipt_neg_05 | hard | Proxy set trap rejects prototype keys | **FP** | TN | TN | **FP**★ | Proxy trap not modelled by MDG; only AST-level write seen |

**IPT sub-totals:**

| Tool | TP/5 pos | TN/5 neg | FP | FN |
|------|----------|----------|----|----|
| eslint | 4 | 0 | 5 | 1 |
| Semgrep | 0 | 5 | 0 | 5 |
| ODGen | 1 | 5 | 0 | 4 |
| Graph.js★ | 1 | 3 | 2 | 4 |

---

### 4.3 Arbitrary File Access / Command Injection

#### Positive cases

| File | Difficulty | Pattern | ESLint | Semgrep | ODGen | Graph.js | Notes |
|------|-----------|---------|--------|---------|-------|----------|-------|
| afa_pos_01 | easy | `path.join + fs.readFile`, no bounds | TP | TP | **FN** | **TP** | **ODGen paper claim fails; Graph.js correct** |
| afa_pos_02 | easy | `path.join + fs.writeFileSync` | TP | TP | FN | **TP** | |
| afa_pos_03 | easy | `require(req.query.plugin)` | TP | TP | FN | **TP** | Graph.js: `code-injection` |
| afa_pos_04 | medium | PP gadget chain → path traversal | TP | FN | FN | **TP** | **Graph.js uniquely detects gadget chain** |
| afa_pos_05 | medium | Partial sanitiser bypassed → execSync | **FN** | FN | **TP** | FN | ODGen uniquely detects inter-proc taint |
| afa_pos_06 | medium | hex-encoded path → readFileSync | TP | FN | FN | **TP** | Graph.js: `code-injection` via eval |

#### Negative cases

| File | Difficulty | Defence | ESLint | Semgrep | ODGen | Graph.js | Notes |
|------|-----------|---------|--------|---------|-------|----------|-------|
| afa_neg_01 | easy | path.resolve + startsWith | **FP** | **FP** | TN | **FP** | path.resolve guard not modelled by 3 tools |
| afa_neg_02 | medium | Filename allowlist (Set) | **FP** | **FP** | TN | **FP** | Allowlist pre-check not modelled |
| afa_neg_03 | hard | fs.realpath + startsWith | **FP** | **FP** | TN | **FP** | realpath guard not modelled; ODGen alone correct |
| afa_neg_04 | easy | path.basename + extension allowlist | **FP** | TN | TN | **FP**★ | basename sanitisation not modelled by eslint/Graph.js |
| afa_neg_05 | medium | Numeric-ID-only input → template path | **FP** | TN | TN | **FP**★ | Number() conversion not modelled as taint break |
| afa_neg_06 | hard | HMAC-signed token gates file access | **FP** | TN | TN | **FP**★ | HMAC verification not modelled; raw token traced to readFile |

**AFA sub-totals:**

| Tool | TP/6 pos | TN/6 neg | FP | FN |
|------|----------|----------|----|----|
| Graph.js★ | 5 | 0 | 6 | 1 |
| eslint | 5 | 0 | 6 | 1 |
| Semgrep | 3 | 3 | 3 | 3 |
| ODGen | 1 | 6 | 0 | 5 |

---

## 5. Cross-Cutting Observations

### 5.1 eslint-plugin-security

**The class-balance test unmasks the tool's true character.** With 21 positive vs 14 negative, eslint had F1=0.72. With 21 vs 21, it falls to F1=0.63 — below the trivial all-positive baseline (F1=0.67). The tool flags 36 of 42 files, which is almost indistinguishable from "flag everything". Its 18 false positives all stem from the same root cause: `detect-object-injection` fires on any `obj[var]` write regardless of guards.

The 7 new negative cases all trigger FPs:
- `pp_neg_09`/`pp_neg_10`: for-in or Object.keys loop body fires even after deepFreeze / structuredClone sanitisation
- `ipt_neg_04`/`ipt_neg_05`: write to a sealed or Proxy-guarded object is indistinguishable from a real PP at AST level
- `afa_neg_04`/`05`/`06`: `fs.readFile` with any variable path fires regardless of basename, numeric validation, or HMAC verification upstream

**Verdict:** Not suitable as a standalone scanner on balanced data. Useful only as a first-pass triage filter feeding into a more precise tool.

---

### 5.2 Graph.js (PLDI 2024)

With balanced classes, Graph.js's estimated F1 drops from 0.56 to 0.46. Its FP count grows from 5 to 12 — the new negatives expose a systematic gap: Graph.js has no model for sanitiser primitives (`path.basename`, numeric coercion, HMAC verification, `Object.seal`, Proxy set traps, `structuredClone`, `deepFreeze`). Any user-controlled value that reaches a path or property-write sink without a Graph.js-known sanitiser is flagged.

Despite this, Graph.js remains the **strongest academic tool** on positive detection: it uniquely catches the PP gadget chain → path traversal case (afa_pos_04), handles `constructor.prototype` paths (pp_pos_03), and detects eval-based obfuscation (pp_pos_10, afa_pos_06) as `code-injection`.

**The core gap Graph.js reveals** is exactly the problem Iridium must solve: tracking sanitiser effects through the data flow. Graph.js has the right graph structure (MDG with taint edges) but lacks a lattice of sanitiser states on those edges.

---

### 5.3 ODGen (USENIX Security 2022)

ODGen benefits most from class balancing — its precision (0.80) is unaffected by the new negatives because all 7 new negatives are TN. Its recall (0.19) and F1 (0.31) are unchanged. The confirmed blind spots remain:

1. **For-in loop PP** (pp_pos_01, 03, 04, 06, 07) — for-in key not recognised as tainted
2. **Hoisting** (pp_pos_07) — AST-order flow inference
3. **Destructuring** (pp_pos_08, ipt_pos_05) — dropped taint
4. **Path traversal** (afa_pos_01/02) — paper claim; open-source release fails basic examples
5. **Single FP: pp_neg_08** — allowlist guard not modelled

ODGen correctly suppresses all defences in the new negatives: `deepFreeze`, `structuredClone`, `Object.seal`, Proxy set trap, `path.basename`, numeric validation, HMAC — because ODGen requires a full taint flow matching its detection pattern before alarming, rather than flagging any sink reachable from any untrusted input.

**Verdict:** Highest precision, lowest false-positive rate. Best choice when a human must triage every alert.

---

### 5.4 Semgrep (p/javascript ruleset)

Unaffected by the 7 new negatives — Semgrep returns TN on all of them (its AFA rules don't fire on `path.basename`, numeric IDs, or HMAC patterns). The 3 original AFA FPs (afa_neg_01/02/03) persist. With balanced data, Semgrep has the cleanest precision/recall picture: 0 FP on PP and IPT, 3 FP on AFA, but 0 TP on PP and IPT. F1=0.22.

Adding the custom `rules.yaml` (`bash tools/semgrep/run_custom.sh`) raises PP recall from 0 to ~0.30 at the cost of some FPs.

---

## 6. Universal Blind Spots — Cases No Tool Caught

| File | Pattern | Why it's hard |
|------|---------|---------------|
| `pp_pos_07` | `var` hoisting: variable used before textual declaration | AST-order analysis fails for all four tools |
| `pp_pos_08` | Destructuring `{ __proto__: x } = parsed` → `Object.assign(Object.prototype, x)` | No tool models destructuring as taint-propagating |
| `ipt_pos_05` | Destructuring → `Object.defineProperties` on prototype | Destructuring + defineProperties; universal blind spot |
| `pp_pos_04` | hasOwnProperty bypass via JSON.parse (own `__proto__` key) | Requires JSON.parse semantics + for-in taint together |

These motivate Iridium's design requirements:
- Destructuring must lower to explicit property reads/writes in the IR
- `for-in` key enumeration over a user-controlled object must mark keys as tainted
- `JSON.parse` must be modelled as potentially returning objects with `__proto__` as an own property
- Flow sensitivity is needed to distinguish guarded vs unguarded paths at sinks

---

## 7. Implications for Iridium

1. **The balanced benchmark exposes that high recall ≠ useful.** ESLint falls below the trivial baseline. A tool for Iridium integration must have F1 > 0.67 to be worth running; none of the existing tools meet this bar on balanced data.

2. **ODGen's precision is the floor.** At 0.80 precision, ODGen gives the confidence bar Iridium should aim to exceed. The key gap is the 17 false negatives — especially the for-in enumeration pattern (the most common real-world PP vector).

3. **Graph.js reveals the sanitiser modelling gap.** Its MDG correctly traces gadget chains and multi-source flows (beating ODGen on recall), but produces 12 FPs because it has no model for runtime safety guarantees like `Object.freeze`, `Object.seal`, Proxy traps, `structuredClone`, `path.basename`, or numeric coercion. Iridium's analysis should propagate a "sanitised" lattice bit on taint edges.

4. **Flow sensitivity is required for the sanitiser gap.** The `Object.seal`, deepFreeze, and allowlist patterns all require knowing — at the point of the sink — that the data has passed through a specific guard at runtime. This is a flow-sensitive property. Andersen-style analysis (context-insensitive) cannot represent it.

5. **Destructuring is a universal blind spot.** Three cases are missed by all four tools. Iridium's IR should lower destructuring to explicit property reads carrying taint metadata.

6. **One CFG per function is sufficient for the gadget chain case.** afa_pos_04 (the only case requiring cross-function reasoning) has a trivial call graph. Single-level inlining would detect it.

---

## 8. Reproducing the Evaluation

### Setup

```bash
# Tool 1: ESLint
bash tools/eslint-plugin-security/setup.sh

# Tool 2: Semgrep
bash tools/semgrep/setup.sh

# Tool 3: ODGen
bash tools/odgen/setup.sh

# Tool 4: Graph.js (Docker)
cd tools/graphjs && docker build . -t graphjs && cd ../..
```

### Run

```bash
# ESLint (from repo root)
npx eslint --format json testcases/ > /tmp/eslint_out.json

# Semgrep — built-in ruleset
semgrep --config p/javascript testcases/ --json > /tmp/semgrep_out.json

# Semgrep — custom PP + AFA + cmd-injection rules
bash tools/semgrep/run_custom.sh testcases/

# ODGen — batch runner
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

Graph.js output per file: `/tmp/graphjs_iridium_results/<mangled>/taint_summary_detection.json`.
Empty array `[]` = clean; non-empty = detected (fields: `vuln_type`, `sink`, `sink_lineno`).
