/*
 * VULNERABILITY : Internal Property Tampering
 * TYPE          : Negative (safe)
 * DIFFICULTY    : Medium
 * DETECTION     : Should NOT be flagged — Object.seal prevents adding new properties
 * STATIC ANALYSIS VERDICT: Safe — the merge target is sealed before untrusted data
 *                 is applied; Object.seal prevents new property creation so prototype
 *                 properties (hasOwnProperty, toString, etc.) cannot be overwritten
 *                 via assignment to the target
 * ATTACK        : Attacker supplies { "hasOwnProperty": "pwned" } hoping to shadow
 *                 the built-in via the merge target
 * EFFECT        : Object.seal marks all existing properties as non-configurable and
 *                 prevents adding new ones — the rogue key is silently dropped (sloppy)
 *                 or throws a TypeError (strict)
 */

'use strict';

/**
 * Merge source into a sealed configuration object.
 * Sealed objects accept writes to existing own properties but reject new keys.
 */
function mergeIntoSealed(sealed, source) {
  for (const key of Object.keys(source)) {
    if (Object.prototype.hasOwnProperty.call(sealed, key)) {
      // Only update keys that already exist on the sealed object
      sealed[key] = source[key];
    }
    // New keys (including prototype-shadowing keys) are silently ignored
  }
  return sealed;
}

// Define the permitted schema up front, then seal it
const defaults = Object.seal({
  timeout: 3000,
  retries: 3,
  endpoint: '/api/v1',
});

// Simulated untrusted user-supplied overrides
const userOptions = JSON.parse(
  '{"timeout":5000,"hasOwnProperty":"evil","constructor":"hack","__proto__":{"x":1}}'
);

try {
  mergeIntoSealed(defaults, userOptions);
} catch (e) {
  console.log('Rejected (strict):', e.message);
}

console.assert(typeof defaults.hasOwnProperty === 'function',
  'SAFE: hasOwnProperty is still the native function');
console.assert(defaults.__proto__ === Object.prototype,
  'SAFE: prototype not changed');
console.log('Config:', defaults);
