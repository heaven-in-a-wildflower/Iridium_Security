// VULNERABILITY: Prototype Pollution via destructuring assignment (CWE-1321)
// TYPE:          positive
// DIFFICULTY:    hard
// DETECTION:     ODGen does not correctly model destructuring assignment.
//                The taint flow is:
//                  user input → JSON.parse → { __proto__: protoPayload } = parsed
//                  → Object.assign(Object.prototype, protoPayload)   ← SINK
//                An analysis that cannot track values through destructuring
//                patterns will fail to connect the source to the sink.
//                Pattern B uses a computed-key destructuring form, which is
//                even harder to model statically.
// STATIC ANALYSIS VERDICT: DETECTABLE in principle; ODGen MISSES this
//
// ATTACK:  configure('{"__proto__": {"x": 1}}')
// EFFECT:  ({}).x === 1

// Pattern A: named destructuring then merge
function configure(rawJson) {
  const parsed = JSON.parse(rawJson);
  const { __proto__: protoPayload, ...rest } = parsed; // destructures __proto__
  if (protoPayload && typeof protoPayload === 'object') {
    // Developer intent: "copy proto fields onto base prototype defaults"
    // Actual effect: directly mutates Object.prototype
    Object.assign(Object.prototype, protoPayload); // SINK
  }
  return rest;
}

// Pattern B: computed-key destructuring
function applyDefaults(base, overrides) {
  const key = '__proto__';
  const { [key]: protoVal } = overrides; // computed-key destructuring of __proto__
  if (protoVal) {
    Object.assign(base.__proto__, protoVal); // SINK
  }
  const { [key]: _, ...safeOverrides } = overrides;
  return Object.assign(base, safeOverrides);
}

module.exports = { configure, applyDefaults };
