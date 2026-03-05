# Internal Property Tampering (CWE-1321 variant)

A sub-class of prototype pollution where the attacker specifically targets
built-in methods (`hasOwnProperty`, `toString`, `Array.prototype.push`,
`Function.prototype.call`, …) rather than injecting arbitrary new properties.
Effect: security checks that rely on these methods silently break or behave
incorrectly.

## Positive cases (vulnerable)

| File           | Difficulty | Target property           | ODGen?      |
|----------------|------------|---------------------------|-------------|
| ipt_pos_01.js  | easy       | hasOwnProperty            | detects     |
| ipt_pos_02.js  | easy       | Array.prototype.push      | detects     |
| ipt_pos_03.js  | medium     | Function.prototype.call   | detects     |
| ipt_pos_04.js  | medium     | Object.prototype.toString | detects     |
| ipt_pos_05.js  | hard       | Object.prototype (via destructuring + defineProperties) | **misses** |

## Negative cases (safe, must not be flagged)

| File           | Difficulty | Defence mechanism                          |
|----------------|------------|--------------------------------------------|
| ipt_neg_01.js  | easy       | Object.freeze on all built-in prototypes   |
| ipt_neg_02.js  | medium     | Symbol-keyed internal methods              |
| ipt_neg_03.js  | hard       | Cached pristine method references + .call()|
