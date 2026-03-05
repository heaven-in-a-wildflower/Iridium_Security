// VULNERABILITY: Prototype Pollution — var hoisting confuses AST-order flow analysis (CWE-1321)
// TYPE:          positive
// DIFFICULTY:    hard
// DETECTION:     `var config` is hoisted to the top of `process()` by the JS
//                runtime, but its *assignment* (`config = {}`) appears in the
//                source text AFTER the `merge(config, …)` call. An analysis
//                that infers data-flow from AST textual order (as ODGen does)
//                sees the call site before the assignment and may record
//                `config` as `undefined` at the call — producing either a
//                missed alarm or a spurious one for the wrong reason.
//                A flow-sensitive analysis with correct hoisting semantics
//                knows `config` is `{}` at the merge call site and correctly
//                reports PP.
// STATIC ANALYSIS VERDICT: DETECTABLE but ODGen has IMPRECISION due to hoisting
//
// ATTACK:  process('{"__proto__": {"hoisted": true}}')
// EFFECT:  ({}).hoisted === true

function process(rawInput) {
  // At runtime: `config` is declared (undefined) here due to var hoisting,
  // but the assignment `config = {}` has NOT executed yet in source order.
  // However, var hoisting in JS means the assignment IS executed before merge
  // only if we move it up — here it is intentionally left below to trigger
  // the hoisting confusion in static analysis.
  merge(config, JSON.parse(rawInput)); // called before textual assignment
  var config = {};                     // assignment comes after in AST order
  return config;
}

function merge(target, source) {
  if (target == null) return;
  for (const key in source) {
    target[key] = source[key]; // no key filtering
  }
}

module.exports = { process };
