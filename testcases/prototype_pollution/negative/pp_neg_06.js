// VULNERABILITY: None — Object.prototype is frozen before any merge runs
// TYPE:          negative
// DIFFICULTY:    medium
// REASON SAFE:   Object.freeze(Object.prototype) makes the prototype immutable.
//                Any attempt to add or overwrite properties on it either throws
//                in strict mode or silently fails in sloppy mode. The merge
//                below looks syntactically identical to a vulnerable one, but
//                at runtime it cannot mutate Object.prototype.
// ANALYSIS NOTE: A static analysis that does not model Object.freeze will flag
//                the for-in loop as a false positive. Correctly suppressing
//                the alarm requires knowing that Object.prototype was frozen
//                earlier in the execution — a flow-sensitive property.
// STATIC ANALYSIS VERDICT: TRUE NEGATIVE (requires modelling Object.freeze)

Object.freeze(Object.prototype);

// This looks like pp_pos_01 but is safe because the prototype is frozen
function unsafeLookingMerge(target, source) {
  for (const key in source) {
    target[key] = source[key];
  }
  return target;
}

module.exports = { unsafeLookingMerge };
