// VULNERABILITY: Prototype Pollution via bracket-notation path parsing (CWE-1321)
// TYPE:          positive
// DIFFICULTY:    medium
// DETECTION:     A regex tokenises both dot and bracket syntax, extracting
//                '__proto__' as a segment from strings like '__proto__[x]'
//                or 'constructor[prototype][y]'. The analysis must model
//                that the regex /[^.[\]]+/g will yield '__proto__' as a token.
// STATIC ANALYSIS VERDICT: DETECTABLE (requires string/regex pattern analysis or
//                conservative approximation that any regex-extracted path token
//                may be a dangerous prototype key)
//
// ATTACK:  set({}, '__proto__[polluted]', true)
//          set({}, 'constructor[prototype][evil]', 1)
// EFFECT:  ({}).polluted === true

function set(object, path, value) {
  // Parses both dot and bracket notation: 'a.b[c]' → ['a','b','c']
  const pathArray = Array.isArray(path)
    ? path
    : path.match(/[^.[\]]+/g) || [];

  pathArray.reduce((acc, key, index) => {
    if (index === pathArray.length - 1) {
      acc[key] = value; // final write — key may be '__proto__'
    } else {
      acc[key] = acc[key] || {};
    }
    return acc[key];
  }, object);

  return object;
}

module.exports = { set };
