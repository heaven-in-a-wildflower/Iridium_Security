// VULNERABILITY: Prototype Pollution via unfiltered for-in merge (CWE-1321)
// TYPE:          positive
// DIFFICULTY:    easy
// DETECTION:     Single-function data-flow: `source` (user-controlled) flows
//                to `target[key]` inside a for-in loop with no key guard.
//                Any analysis that tracks taint from the parameter to a
//                property-write sink will flag this.
// STATIC ANALYSIS VERDICT: DETECTABLE (conservative)
//
// ATTACK:  merge({}, JSON.parse('{"__proto__": {"isAdmin": true}}'))
// EFFECT:  ({}).isAdmin === true — every new plain object gains isAdmin

function merge(target, source) {
  for (let key in source) {
    target[key] = source[key]; // key can be "__proto__"
  }
  return target;
}

module.exports = { merge };
