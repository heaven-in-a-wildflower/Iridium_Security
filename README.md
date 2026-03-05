# Iridium Security Testbench

Static-analysis testbench for JavaScript vulnerability detection, developed
alongside the Iridium compiler framework. The test cases guide precision/
efficiency trade-offs in points-to and taint analysis.

## Repository Layout

```
testcases/                   ← all test cases (this is the primary artifact)
  prototype_pollution/       ← CWE-1321
    positive/                ← vulnerable code  (analysis MUST report)
    negative/                ← safe code        (analysis must NOT report — FP if flagged)
  internal_property_tampering/
    positive/
    negative/
  arbitrary_file_access/     ← CWE-22 / CWE-78
    positive/
    negative/
artifacts/
  ODGen/                     ← ODGen submodule (USENIX 22)
  microbenchmarks/           ← original exploratory sketches (historical)
papers/
  dependency-graph/          ← ODGen, ODGen-Fast, explode.js (PLDI 25), graph.js
  prototype-pollution/       ← GHunter, Silent Spring, o_arteau, objlupansys, uopf
  xss/                       ← DOM-XSS, second-order XSS, Lekies, …
  icse2020_Taser.pdf
  lynx.pdf
```

## Naming Convention

Files are named `<prefix>_pos_NN.js` or `<prefix>_neg_NN.js` where **NN increases
with detection difficulty**.

| NN    | Difficulty            | What is required of the analysis                           |
|-------|-----------------------|------------------------------------------------------------|
| 01–03 | Easy                  | Pattern matching / basic data-flow                         |
| 04–06 | Medium                | Inter-procedural or context-sensitive tracking             |
| 07–08 | Hard                  | Flow sensitivity, destructuring, complex aliasing          |
| 09–10 | Undecidable (conservative) | Only detectable dynamically; conservative analysis must over-approximate |

## Vulnerability Types

| Prefix | Vulnerability                    | CWE        |
|--------|----------------------------------|------------|
| `pp`   | Prototype Pollution              | CWE-1321   |
| `ipt`  | Internal Property Tampering      | CWE-1321 variant |
| `afa`  | Arbitrary File Access / Cmd Injection | CWE-22 / CWE-78 |

## Background & Motivation

Based on analysis of ODGen (USENIX 22) and explode.js (PLDI 25).
ODGen limitations identified:
- **Hoisting imprecision** — infers flow from AST order, confused by `var` hoisting
- **Destructuring blind spot** — does not model destructuring assignment
- **Arbitrary file access** — paper claims detection but fails on basic examples

Conclusion: basic Andersen-style analysis is insufficient; flow sensitivity is
required. One CFG per function is a viable starting point. These test cases
are designed to drive and validate that implementation.
