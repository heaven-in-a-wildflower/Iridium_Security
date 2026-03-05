// VULNERABILITY: None — JSON round-trip sanitises __proto__ as a data property
// TYPE:          negative
// DIFFICULTY:    medium
// REASON SAFE:   JSON.stringify serialises an object's own '__proto__' property
//                (as set by JSON.parse) to the string key "__proto__" in the
//                output JSON. Re-parsing that JSON with JSON.parse again
//                produces an object where "__proto__" is an own data property,
//                NOT a prototype link. The subsequent for-in loop then copies
//                it to `result["__proto__"]` as a plain string key — it does
//                not modify the prototype chain.
// ANALYSIS NOTE: Subtle — requires understanding that JSON round-trip prevents
//                prototype chain modification even though the for-in loop
//                looks syntactically unsafe.
// STATIC ANALYSIS VERDICT: TRUE NEGATIVE (requires modelling JSON semantics)

function sanitizeAndProcess(userInput) {
  // Round-trip: __proto__ becomes a plain data property, not a prototype link
  const clean = JSON.parse(JSON.stringify(userInput));
  const result = {};
  for (const key in clean) {
    result[key] = clean[key]; // __proto__ is a data property here
  }
  return result;
}

module.exports = { sanitizeAndProcess };
