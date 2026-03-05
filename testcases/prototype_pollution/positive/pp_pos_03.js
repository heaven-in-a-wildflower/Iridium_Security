// VULNERABILITY: Prototype Pollution via constructor.prototype path (CWE-1321)
// TYPE:          positive
// DIFFICULTY:    easy
// DETECTION:     Same dot-path pattern as pp_pos_02, but exploited via the
//                'constructor.prototype' route rather than '__proto__'.
//                An analysis that only blocks '__proto__' as a literal string
//                will miss this variant; one that blocks 'constructor' as a
//                path segment will catch it.
// STATIC ANALYSIS VERDICT: DETECTABLE (conservative; requires blocking 'constructor')
//
// ATTACK:  deepSet({}, 'constructor.prototype.admin', true)
// EFFECT:  ({}).admin === true — pollutes through constructor chain

function deepSet(obj, keyPath, value) {
  const keys = keyPath.split('.');
  let curr = obj;
  for (let i = 0; i < keys.length - 1; i++) {
    if (!curr[keys[i]]) curr[keys[i]] = {};
    curr = curr[keys[i]];
  }
  curr[keys[keys.length - 1]] = value;
  return obj;
}

module.exports = { deepSet };
