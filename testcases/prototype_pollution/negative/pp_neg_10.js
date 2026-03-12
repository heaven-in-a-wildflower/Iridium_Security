/*
 * VULNERABILITY : Prototype Pollution
 * TYPE          : Negative (safe)
 * DIFFICULTY    : Hard
 * DETECTION     : Should NOT be flagged — structuredClone strips prototype chain
 * STATIC ANALYSIS VERDICT: Safe — structuredClone produces a plain-object clone
 *                 that carries no prototype references, so __proto__ key in the
 *                 source is dropped before any merge touches it
 * ATTACK        : Attacker supplies { "__proto__": { "isAdmin": true } }
 * EFFECT        : structuredClone serialises and deserialises through the structured
 *                 clone algorithm, which does NOT copy the __proto__ accessor or
 *                 non-plain prototype links — result is a clean plain object
 */

'use strict';

/**
 * Safe deep merge: sanitise input with structuredClone first.
 * structuredClone uses the HTML structured clone algorithm — it copies enumerable
 * own properties into a fresh object graph, but __proto__ is not an own property
 * (it is an accessor on Object.prototype) and is therefore not transferred.
 */
function safeMerge(target, untrustedSource) {
  // structuredClone isolates the clone from the source's prototype chain
  const safeSource = structuredClone(untrustedSource);

  for (const key of Object.keys(safeSource)) {
    if (typeof safeSource[key] === 'object' && safeSource[key] !== null
        && typeof target[key] === 'object' && target[key] !== null) {
      safeMerge(target[key], safeSource[key]);
    } else {
      target[key] = safeSource[key];
    }
  }
  return target;
}

// Simulate attacker-controlled input
const maliciousInput = JSON.parse('{"__proto__":{"polluted":true},"role":"user"}');

const appConfig = { role: 'guest', theme: 'light' };
safeMerge(appConfig, maliciousInput);

const probe = {};
console.assert(probe.polluted === undefined, 'SAFE: prototype chain not polluted');
console.log('Config after merge:', appConfig);
