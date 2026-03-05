// VULNERABILITY: Internal Property Tampering — Object.prototype.toString spoofing (CWE-1321 variant)
// TYPE:          positive
// DIFFICULTY:    medium
// DETECTION:     updateOptions performs a shallow merge that includes the key
//                'toString'. Writing to defaults['toString'] overwrites the
//                inherited Object.prototype.toString on the returned object.
//                Downstream type-checking code that relies on toString for
//                type tagging can then be spoofed.
//                Requires inter-procedural tracking from updateOptions to
//                the downstream validateType call.
// STATIC ANALYSIS VERDICT: DETECTABLE (inter-procedural taint tracking)
//
// ATTACK:  updateOptions({}, { toString: () => '[object Admin]' })
// EFFECT:  validateType(result, 'Admin') returns true for any object

function updateOptions(defaults, overrides) {
  for (const key in overrides) {
    defaults[key] = overrides[key]; // 'toString' key overwrites the method
  }
  return defaults;
}

// Security check that relies on toString for type tagging (can be spoofed):
function validateType(obj, expectedType) {
  const tag = Object.prototype.toString.call(obj); // uses the potentially spoofed toString
  return tag === `[object ${expectedType}]`;
}

module.exports = { updateOptions, validateType };
