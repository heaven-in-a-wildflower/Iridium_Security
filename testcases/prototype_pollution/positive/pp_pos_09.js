// VULNERABILITY: Prototype Pollution via Proxy set trap (CWE-1321)
// TYPE:          positive
// DIFFICULTY:    undecidable (conservative static analysis)
// DETECTION:     The property name reaching the Proxy `set` trap is determined
//                at runtime via Object.entries on a JSON-parsed object.
//                Object.entries() DOES yield '__proto__' when it is an own
//                property (as produced by JSON.parse). A conservative static
//                analysis cannot enumerate all strings that Object.entries
//                may produce without dynamic information. A sound analysis
//                must over-approximate: flag ANY Proxy `set` trap as potentially
//                receiving '__proto__', which causes excessive false positives
//                on all Proxy-using code.
// STATIC ANALYSIS VERDICT: NOT CONSERVATIVELY DECIDABLE without FP explosion
//
// ATTACK:  mergeViaProxy({}, JSON.parse('{"__proto__": {"injected": true}}'))
// EFFECT:  target.__proto__ is replaced; all objects inheriting from it
//          gain .injected === true
//
// NOTE: Object.entries on a JSON-parsed object yields ["__proto__", {...}]
//       because JSON.parse makes __proto__ an own enumerable property.
//       proxy[prop] = val with prop === "__proto__" then replaces the
//       target's [[Prototype]] slot (not Object.prototype — but the target
//       and all objects delegating to it are affected).

function createMergingProxy(target) {
  return new Proxy(target, {
    set(obj, prop, value) {
      // At analysis time: prop is an unknown string; may be '__proto__'
      obj[prop] = value;
      return true;
    }
  });
}

function mergeViaProxy(target, source) {
  const proxy = createMergingProxy(target);
  for (const [prop, val] of Object.entries(source)) {
    proxy[prop] = val; // prop may be '__proto__' for JSON-parsed source
  }
  return target;
}

module.exports = { mergeViaProxy };
