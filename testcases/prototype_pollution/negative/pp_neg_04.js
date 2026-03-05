// VULNERABILITY: None — Map/WeakMap store data outside the prototype chain
// TYPE:          negative
// DIFFICULTY:    easy
// REASON SAFE:   Map and WeakMap entries exist in an internal slot completely
//                separate from [[Prototype]]. Setting a Map key to '__proto__'
//                creates a Map entry, not a prototype link. No attacker-
//                controlled Map key can pollute Object.prototype.
// STATIC ANALYSIS VERDICT: TRUE NEGATIVE

function buildIndex(entries) {
  const index = new Map();
  for (const [key, value] of entries) {
    index.set(key, value); // Map key — no prototype chain involved
  }
  return index;
}

const _cache = new WeakMap();

function getOrCompute(obj, computeFn) {
  if (!_cache.has(obj)) {
    _cache.set(obj, computeFn(obj));
  }
  return _cache.get(obj);
}

module.exports = { buildIndex, getOrCompute };
