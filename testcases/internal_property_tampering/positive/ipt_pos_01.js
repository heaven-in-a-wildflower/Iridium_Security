// VULNERABILITY: Internal Property Tampering — overwriting Object.prototype.hasOwnProperty (CWE-1321 variant)
// TYPE:          positive
// DIFFICULTY:    easy
// DETECTION:     A for-in loop copies user-controlled keys to a result object
//                without filtering. If the user provides the key 'hasOwnProperty',
//                it overwrites the inherited method on the result object.
//                All subsequent calls to result.hasOwnProperty() then invoke
//                the attacker-supplied value instead, defeating key-safety
//                checks that rely on it. The taint path is trivially visible
//                in a single function.
// STATIC ANALYSIS VERDICT: DETECTABLE
//
// ATTACK:  buildResult(JSON.parse('{"hasOwnProperty": "PWNED"}'))
// EFFECT:  result.hasOwnProperty('x') === 'PWNED'  — security checks bypassed

function buildResult(userInput) {
  const result = {};
  for (const key in userInput) {
    result[key] = userInput[key]; // 'hasOwnProperty' key overwrites the method
  }
  return result;
}

// Downstream check that breaks after tampering:
function isOwn(obj, key) {
  return obj.hasOwnProperty(key); // may now call attacker-supplied value
}

module.exports = { buildResult, isOwn };
