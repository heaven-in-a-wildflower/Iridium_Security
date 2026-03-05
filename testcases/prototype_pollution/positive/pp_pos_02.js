// VULNERABILITY: Prototype Pollution via dot-path assignment (CWE-1321)
// TYPE:          positive
// DIFFICULTY:    easy
// DETECTION:     Path string is user-controlled; split on '.' produces key
//                segments that are assigned without filtering '__proto__' or
//                'constructor'/'prototype'. Direct taint from `path` parameter
//                to `current[keys[i]]` write.
// STATIC ANALYSIS VERDICT: DETECTABLE (conservative)
//
// ATTACK:  setProperty({}, '__proto__.polluted', 'yes')
// EFFECT:  ({}).polluted === 'yes'

function setProperty(obj, path, value) {
  const keys = path.split('.');
  let current = obj;
  for (let i = 0; i < keys.length - 1; i++) {
    current[keys[i]] = current[keys[i]] || {};
    current = current[keys[i]];
  }
  current[keys[keys.length - 1]] = value;
  return obj;
}

module.exports = { setProperty };
