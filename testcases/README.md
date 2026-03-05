# Testcases

## Directory Overview

```
prototype_pollution/
  positive/   pp_pos_01 … pp_pos_10   (01=easy → 10=undecidable)
  negative/   pp_neg_01 … pp_neg_08

internal_property_tampering/
  positive/   ipt_pos_01 … ipt_pos_05
  negative/   ipt_neg_01 … ipt_neg_03

arbitrary_file_access/
  positive/   afa_pos_01 … afa_pos_06
  negative/   afa_neg_01 … afa_neg_03
```

## Classification

- **positive** — contains a real vulnerability; a correct analysis **must** report it.
- **negative** — safe code; a correct analysis **must not** report it (a report is a false positive).

## Difficulty Scale

| Range | Label        | Analysis required                                             |
|-------|--------------|---------------------------------------------------------------|
| 01–03 | Easy         | Single-function data-flow / pattern match on `__proto__`      |
| 04–06 | Medium       | Inter-procedural taint; `hasOwnProperty` bypass via JSON.parse|
| 07–08 | Hard         | Flow sensitivity; `var` hoisting; destructuring assignment     |
| 09–10 | Undecidable† | Proxy traps, `eval`, runtime-decoded strings                  |

†  A *sound* static analysis must over-approximate these; doing so causes
   false positives elsewhere. They are only reliably caught dynamically.

## Header Format

Every file begins with a comment block:

```
// VULNERABILITY: <description> (CWE-NNNN)
// TYPE:          positive | negative
// DIFFICULTY:    easy | medium | hard | undecidable
// DETECTION:     <what the analysis needs to do>
// STATIC ANALYSIS VERDICT: DETECTABLE | NOT CONSERVATIVELY DECIDABLE | TRUE NEGATIVE
//
// ATTACK:  <exploit invocation>
// EFFECT:  <what happens>
```

## ODGen-Specific Notes

| File           | ODGen behaviour                                             |
|----------------|-------------------------------------------------------------|
| `pp_pos_07.js` | Imprecision due to `var` hoisting                          |
| `pp_pos_08.js` | Missed — destructuring not modelled                        |
| `ipt_pos_05.js`| Missed — destructuring not modelled                        |
| `afa_pos_01.js`| Paper claims detection; tool fails on this basic example   |
