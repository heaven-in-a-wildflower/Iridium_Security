// VULNERABILITY: None — internal methods invoked via Object.prototype.X.call()
// TYPE:          negative
// DIFFICULTY:    hard
// REASON SAFE:   All security-sensitive built-in methods are invoked by
//                caching a reference to the pristine prototype method and
//                calling it with .call(). Even if an attacker tampers with
//                an object's inherited .hasOwnProperty or .toString via
//                property assignment, the cached reference points to the
//                original method and is unaffected.
// ANALYSIS NOTE: An imprecise analysis may flag the merge below as dangerous.
//                Correctly suppressing the alarm requires understanding that
//                the cached method references are obtained BEFORE any user
//                data is processed and cannot be overwritten.
// STATIC ANALYSIS VERDICT: TRUE NEGATIVE (requires modelling cached-reference pattern)

// Cache pristine references before any user data is processed
const hasOwn  = Object.prototype.hasOwnProperty;
const toString = Object.prototype.toString;

function safeHasOwn(obj, key) {
  return hasOwn.call(obj, key); // tamper-resistant
}

function safeTypeTag(val) {
  return toString.call(val); // tamper-resistant
}

function defensiveMerge(target, source) {
  for (const key in source) {
    if (!safeHasOwn(source, key)) continue;
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    target[key] = source[key];
  }
  return target;
}

module.exports = { safeHasOwn, safeTypeTag, defensiveMerge };
