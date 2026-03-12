/*
 * VULNERABILITY : Internal Property Tampering
 * TYPE          : Negative (safe)
 * DIFFICULTY    : Hard
 * DETECTION     : Should NOT be flagged — Proxy intercepts all writes and rejects
 *                 keys that shadow prototype properties
 * STATIC ANALYSIS VERDICT: Safe — a Proxy set trap validates every property write;
 *                 keys matching any property on Object.prototype or Function.prototype
 *                 are rejected before reaching the underlying target
 * ATTACK        : Attacker supplies { "push": "evil", "hasOwnProperty": "hack" }
 *                 hoping to overwrite inherited properties via the merge
 * EFFECT        : The Proxy set trap catches prototype-shadowing keys and throws;
 *                 no built-in property is ever overwritten
 */

'use strict';

// Build the set of all enumerable + non-enumerable own names on the base prototypes
const PROTOTYPE_KEYS = new Set([
  ...Object.getOwnPropertyNames(Object.prototype),
  ...Object.getOwnPropertyNames(Function.prototype),
  ...Object.getOwnPropertyNames(Array.prototype),
]);

/**
 * Wrap a plain object in a Proxy that rejects writes to any key that exists
 * on the standard built-in prototypes.
 */
function makeGuardedObject(init = {}) {
  return new Proxy(init, {
    set(target, prop, value, receiver) {
      if (PROTOTYPE_KEYS.has(String(prop))) {
        throw new TypeError(
          `Blocked: attempt to shadow built-in property "${String(prop)}"`
        );
      }
      return Reflect.set(target, prop, value, receiver);
    },
  });
}

/**
 * Merge untrusted source into a guarded object.
 * Any key that matches a prototype property will throw inside makeGuardedObject.
 */
function guardedMerge(source) {
  const target = makeGuardedObject();
  for (const [key, val] of Object.entries(source)) {
    try {
      target[key] = val;
    } catch (e) {
      console.warn(`Blocked write of key "${key}":`, e.message);
    }
  }
  return target;
}

// Simulate attacker-supplied object
const untrusted = {
  username: 'alice',
  push: 'EVIL',
  hasOwnProperty: () => true,
  toString: () => 'hacked',
};

const result = guardedMerge(untrusted);

console.assert(Array.prototype.push !== 'EVIL', 'SAFE: Array.prototype.push intact');
console.assert(typeof Object.prototype.hasOwnProperty === 'function',
  'SAFE: hasOwnProperty intact');
console.log('Merged result:', result);
