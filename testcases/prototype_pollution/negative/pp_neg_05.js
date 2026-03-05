// VULNERABILITY: None — explicit blocklist for dangerous prototype keys
// TYPE:          negative
// DIFFICULTY:    medium
// REASON SAFE:   Every key is checked against a Set of prototype-polluting
//                names before assignment. Reflect.ownKeys is used so that
//                non-enumerable and symbol keys are also examined. The
//                blocklist covers all three pollution entry points:
//                __proto__, constructor, and prototype.
// ANALYSIS NOTE: An imprecise analysis may still flag the assignment on line
//                `target[key] = val` without modelling the DANGEROUS_KEYS
//                guard above it. Whether this is a FP depends on the analysis'
//                ability to track the boolean guard.
// STATIC ANALYSIS VERDICT: TRUE NEGATIVE (requires modelling the blocklist guard)

const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function safeMerge(target, source) {
  for (const key of Reflect.ownKeys(source)) {
    if (typeof key === 'symbol') continue;
    if (DANGEROUS_KEYS.has(key)) continue;        // blocklist guard
    const val = source[key];
    if (val !== null && typeof val === 'object') {
      target[key] = target[key] && typeof target[key] === 'object'
        ? safeMerge(target[key], val)
        : safeMerge({}, val);
    } else {
      target[key] = val;
    }
  }
  return target;
}

module.exports = { safeMerge };
