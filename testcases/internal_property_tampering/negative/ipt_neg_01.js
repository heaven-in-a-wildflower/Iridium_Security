// VULNERABILITY: None — all built-in prototypes are frozen
// TYPE:          negative
// DIFFICULTY:    easy
// REASON SAFE:   Object.prototype, Array.prototype, and Function.prototype are
//                all frozen. Any attempt to add or overwrite their properties
//                (including hasOwnProperty, push, call, toString) throws in
//                strict mode or silently fails in sloppy mode. The merge below
//                looks dangerous but cannot tamper with any built-in method.
// STATIC ANALYSIS VERDICT: TRUE NEGATIVE (requires modelling Object.freeze)

'use strict';
Object.freeze(Object.prototype);
Object.freeze(Array.prototype);
Object.freeze(Function.prototype);

function mergeAll(target, source) {
  for (const key in source) {
    target[key] = source[key]; // frozen prototypes absorb any would-be tampering
  }
  return target;
}

module.exports = { mergeAll };
