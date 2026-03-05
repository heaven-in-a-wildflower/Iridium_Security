// VULNERABILITY: PP-enabled Path Traversal — Silent Spring style gadget (CWE-1321 + CWE-22)
// TYPE:          positive
// DIFFICULTY:    medium
// DETECTION:     Two-stage exploit (PP gadget chain as described in Silent Spring, KTH 2023):
//                  Stage 1 — merge() pollutes Object.prototype.base via for-in.
//                  Stage 2 — readUserFile() reads options.base to determine the
//                    root directory. When options is {}, the lookup falls through
//                    to Object.prototype and returns the attacker-injected value.
//                The PP source is detectable in isolation (same as pp_pos_01).
//                Detecting the full chain requires gadget-chain analysis linking
//                the pollution to the path-construction downstream.
// STATIC ANALYSIS VERDICT: Stage 1 DETECTABLE; full chain requires gadget analysis
//
// ATTACK:
//   merge({}, JSON.parse('{"__proto__": {"base": "/"}}'))
//   readUserFile('etc/passwd', {})   → reads /etc/passwd
// EFFECT:  Arbitrary file read via PP-injected base path

const fs   = require('fs');
const path = require('path');

// Stage 1: PP source — vulnerable merge (same as pp_pos_01)
function merge(target, source) {
  for (const key in source) {
    target[key] = source[key];
  }
}

// Stage 2: gadget — options.base falls through to polluted Object.prototype
function readUserFile(filename, options) {
  // options.base is undefined on a clean {} but resolves to '/' after pollution
  const base = options.base || '/var/www/uploads'; // GADGET: reads from prototype
  const fullPath = path.join(base, filename);
  return fs.readFileSync(fullPath, 'utf8');         // SINK
}

module.exports = { merge, readUserFile };
