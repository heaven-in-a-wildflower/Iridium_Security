// VULNERABILITY: Internal Property Tampering — overwriting Function.prototype.call (CWE-1321 variant)
// TYPE:          positive
// DIFFICULTY:    medium
// DETECTION:     The code writes directly to `fn.__proto__[key]` where `fn` is
//                a plain function and `userInput` is attacker-controlled.
//                Function.prototype is the [[Prototype]] of all functions, so
//                writing to fn.__proto__ writes to Function.prototype.
//                The analysis must track that fn.__proto__ resolves to
//                Function.prototype and that a write to it affects all functions.
// STATIC ANALYSIS VERDICT: DETECTABLE (requires modelling fn.__proto__ as Function.prototype)
//
// ATTACK:  polluteFunctionCall(JSON.parse('{"call": "PWNED"}'))
// EFFECT:  (function(){}).call(null) === 'PWNED' — all .call() invocations broken

function polluteFunctionCall(userInput) {
  const fn = function() {};
  // fn.__proto__ === Function.prototype — write here affects all functions
  for (const key in userInput) {
    fn.__proto__[key] = userInput[key]; // SINK: direct __proto__ write
  }
}

module.exports = { polluteFunctionCall };
