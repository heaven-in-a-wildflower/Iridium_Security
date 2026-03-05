// VULNERABILITY: None — safe merge using Object.assign
// TYPE:          negative
// DIFFICULTY:    easy
// REASON SAFE:   Object.assign copies OWN ENUMERABLE string-keyed properties.
//                It does not traverse the prototype chain. Even if a source
//                has '__proto__' as an own data property (from JSON.parse),
//                Object.assign treats it as a regular property on the result
//                object, not as a prototype link. Object.prototype is never
//                modified.
// STATIC ANALYSIS VERDICT: TRUE NEGATIVE (no false positive expected)

function mergeConfig(defaults, userConfig) {
  return Object.assign({}, defaults, userConfig);
}

module.exports = { mergeConfig };
