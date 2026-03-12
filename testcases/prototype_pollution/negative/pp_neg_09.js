/*
 * VULNERABILITY : Prototype Pollution
 * TYPE          : Negative (safe)
 * DIFFICULTY    : Medium
 * DETECTION     : Should NOT be flagged — deep-freeze guard prevents pollution
 * STATIC ANALYSIS VERDICT: Safe — Object.prototype is frozen before any merge
 * ATTACK        : Attacker supplies { "__proto__": { "admin": true } } as payload
 * EFFECT        : Object.prototype is already deeply frozen; assignment throws in
 *                 strict mode and is silently ignored in sloppy mode — no pollution
 */

'use strict';

/**
 * Recursively freeze an object and all of its enumerable properties.
 * After this call, no new properties can be added to any reachable object.
 */
function deepFreeze(obj) {
  Object.getOwnPropertyNames(obj).forEach(name => {
    const val = obj[name];
    if (val && typeof val === 'object') deepFreeze(val);
  });
  return Object.freeze(obj);
}

// Freeze the entire prototype chain before the server starts accepting input.
deepFreeze(Object.prototype);
deepFreeze(Function.prototype);
deepFreeze(Array.prototype);

/**
 * Generic recursive merge — looks identical to a vulnerable merge, but runs
 * after the deep-freeze above.  Any write to Object.prototype via __proto__ or
 * constructor.prototype will either throw (strict) or silently fail (sloppy).
 */
function merge(target, source) {
  for (const key in source) {
    if (source.hasOwnProperty(key)) {
      if (typeof source[key] === 'object' && source[key] !== null) {
        if (!target[key]) target[key] = {};
        merge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
  }
  return target;
}

// Simulated user payload
const userPayload = JSON.parse('{"__proto__":{"admin":true},"name":"Alice"}');
const config = {};
try {
  merge(config, userPayload);
} catch (e) {
  // Expected in strict mode when prototype is frozen
}

const testObj = {};
console.assert(testObj.admin === undefined, 'SAFE: Object.prototype not polluted');
console.log('Result:', config);
