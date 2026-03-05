// VULNERABILITY: None — safe merge via spread operator
// TYPE:          negative
// DIFFICULTY:    easy
// REASON SAFE:   Spread syntax copies own enumerable properties and does NOT
//                set __proto__ as a prototype link. The expression { ...obj }
//                treats the key '__proto__' as a plain data property named
//                literally "__proto__", leaving Object.prototype untouched.
// STATIC ANALYSIS VERDICT: TRUE NEGATIVE

function configureOptions(defaults, overrides) {
  return { ...defaults, ...overrides };
}

module.exports = { configureOptions };
