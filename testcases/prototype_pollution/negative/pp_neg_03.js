// VULNERABILITY: None — null-prototype objects cannot be polluted
// TYPE:          negative
// DIFFICULTY:    easy
// REASON SAFE:   Object.create(null) produces an object with NO [[Prototype]].
//                Assigning any key — including '__proto__' — only creates a
//                data property on that object. There is no prototype chain to
//                climb, so Object.prototype is never reached.
// STATIC ANALYSIS VERDICT: TRUE NEGATIVE

function parseParameters(input) {
  const params = Object.create(null); // no prototype — immune to pollution
  for (const pair of input.split('&')) {
    const [key, value] = pair.split('=');
    params[key] = decodeURIComponent(value || ''); // plain data write, safe
  }
  return params;
}

module.exports = { parseParameters };
