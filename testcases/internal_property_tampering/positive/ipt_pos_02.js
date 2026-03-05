// VULNERABILITY: Internal Property Tampering — overwriting Array.prototype.push via PP (CWE-1321 variant)
// TYPE:          positive
// DIFFICULTY:    easy
// DETECTION:     Unfiltered recursive deep merge reaches Array.prototype when
//                the source payload is {"__proto__": {"push": null}}.
//                After pollution all array push() calls throw TypeError,
//                enabling denial-of-service or logic subversion in any
//                downstream code that pushes to arrays.
// STATIC ANALYSIS VERDICT: DETECTABLE (same for-in / no-filter pattern as pp_pos_01)
//
// ATTACK:  deepMerge([], JSON.parse('{"__proto__": {"push": null}}'))
// EFFECT:  [].push(1) throws TypeError — all array pushes in the process fail

function deepMerge(target, source) {
  for (const key in source) {
    if (source[key] !== null && typeof source[key] === 'object') {
      target[key] = target[key] || {};
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key]; // SINK: can overwrite Array.prototype.push
    }
  }
  return target;
}

module.exports = { deepMerge };
