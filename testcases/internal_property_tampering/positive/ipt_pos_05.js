// VULNERABILITY: Internal Property Tampering via destructuring — ODGen blind spot (CWE-1321 variant)
// TYPE:          positive
// DIFFICULTY:    hard
// DETECTION:     ODGen does not model destructuring assignment. The taint path:
//                  user input → JSON.parse → { __proto__: protoProps } = config
//                  → Object.defineProperties(Object.getPrototypeOf(base), …)  ← SINK
//                cannot be followed by ODGen because it loses track of the
//                value extracted through destructuring.
//                A flow-sensitive analysis with destructuring support would
//                track protoProps as a tainted value and report the sink.
// STATIC ANALYSIS VERDICT: DETECTABLE in principle; ODGen MISSES this
//
// ATTACK:  enrichPrototype({}, JSON.parse('{"__proto__": {"isAdmin": true}}'))
// EFFECT:  ({}).isAdmin === true via Object.defineProperties on Object.prototype

function enrichPrototype(base, config) {
  // Destructuring assigns the value of __proto__ key to protoProps
  const { __proto__: protoProps, ...ownProps } = config;

  if (protoProps && typeof protoProps === 'object') {
    // Developer intent: "add default methods to the base prototype"
    // Actual effect: writes directly onto Object.prototype
    Object.defineProperties(
      Object.getPrototypeOf(base), // resolves to Object.prototype for plain {}
      Object.fromEntries(
        Object.entries(protoProps).map(([k, v]) => [
          k, { value: v, writable: true, enumerable: true, configurable: true }
        ])
      )
    ); // SINK: defineProperties on Object.prototype
  }

  return Object.assign(base, ownProps);
}

module.exports = { enrichPrototype };
