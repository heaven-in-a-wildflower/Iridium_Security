// VULNERABILITY: Prototype Pollution via recursive deep merge with hasOwnProperty bypass (CWE-1321)
// TYPE:          positive
// DIFFICULTY:    medium
// DETECTION:     hasOwnProperty check appears to be a guard but is ineffective
//                when input comes from JSON.parse. JSON.parse('{"__proto__":{...}}')
//                produces an object where __proto__ IS an own (data) property,
//                so hasOwnProperty returns true, and the key passes the guard.
//                The analysis must model JSON.parse semantics to understand this.
// STATIC ANALYSIS VERDICT: DETECTABLE (requires modelling JSON.parse own-property semantics)
//
// ATTACK:  extend({}, JSON.parse('{"__proto__": {"polluted": true}}'))
// EFFECT:  ({}).polluted === true

function extend(target, ...sources) {
  for (const source of sources) {
    for (const key in source) {
      if (source.hasOwnProperty(key)) {           // looks safe — but JSON.parse makes
        if (typeof source[key] === 'object' &&    // __proto__ an OWN property, so this
            source[key] !== null) {               // check passes for the attack payload
          target[key] = extend({}, source[key]);  // recurse: assigns target['__proto__']
        } else {
          target[key] = source[key];
        }
      }
    }
  }
  return target;
}

module.exports = { extend };
