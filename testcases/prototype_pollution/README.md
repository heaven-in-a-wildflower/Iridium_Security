# Prototype Pollution (CWE-1321)

An attacker injects properties into `Object.prototype` (or a constructor's
`.prototype`) so that all objects in the process inherit the attacker-controlled
value via the prototype chain.

## Positive cases (vulnerable)

| File          | Difficulty    | Key pattern                                          | ODGen?      |
|---------------|---------------|------------------------------------------------------|-------------|
| pp_pos_01.js  | easy          | for-in, no filter                                    | detects     |
| pp_pos_02.js  | easy          | dot-path split, no filter                            | detects     |
| pp_pos_03.js  | easy          | constructor.prototype path variant                   | detects     |
| pp_pos_04.js  | medium        | recursive merge + `hasOwnProperty` bypass via JSON   | detects     |
| pp_pos_05.js  | medium        | bracket-notation regex path parsing                  | detects     |
| pp_pos_06.js  | medium        | multiple input surfaces (URL / JSON Patch / array)   | detects     |
| pp_pos_07.js  | hard          | `var` hoisting confuses AST-order flow               | imprecise   |
| pp_pos_08.js  | hard          | destructuring assignment (`{ __proto__: x } = obj`)  | **misses**  |
| pp_pos_09.js  | undecidable   | Proxy set trap + runtime Object.entries              | undecidable |
| pp_pos_10.js  | undecidable   | eval + Base64-decoded key                            | undecidable |

## Negative cases (safe, must not be flagged)

| File          | Difficulty    | Defence mechanism                                    |
|---------------|---------------|------------------------------------------------------|
| pp_neg_01.js  | easy          | Object.assign                                        |
| pp_neg_02.js  | easy          | spread operator                                      |
| pp_neg_03.js  | easy          | Object.create(null)                                  |
| pp_neg_04.js  | easy          | Map / WeakMap                                        |
| pp_neg_05.js  | medium        | Reflect.ownKeys + DANGEROUS_KEYS blocklist           |
| pp_neg_06.js  | medium        | Object.freeze(Object.prototype)                      |
| pp_neg_07.js  | medium        | JSON round-trip sanitisation                         |
| pp_neg_08.js  | hard          | allowlist + schema validation (early-exit guard)     |
