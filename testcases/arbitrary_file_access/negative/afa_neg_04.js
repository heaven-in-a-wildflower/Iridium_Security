/*
 * VULNERABILITY : Arbitrary File Access
 * TYPE          : Negative (safe)
 * DIFFICULTY    : Easy
 * DETECTION     : Should NOT be flagged — basename extraction eliminates directory
 *                 components; extension allowlist prevents arbitrary file types
 * STATIC ANALYSIS VERDICT: Safe — path.basename strips all directory separators,
 *                 so '../../../etc/passwd' becomes 'passwd' which then fails the
 *                 extension check; only '.txt' and '.json' files from the static dir
 * ATTACK        : req.params.filename = '../../etc/shadow' or '/etc/passwd'
 * EFFECT        : path.basename('../../etc/shadow') === 'shadow'; 'shadow' has no
 *                 allowed extension → 404 returned before any fs call
 */

'use strict';

const path = require('path');
const fs   = require('fs');

const STATIC_DIR     = path.resolve(__dirname, 'public');
const ALLOWED_EXTS   = new Set(['.txt', '.json']);

/**
 * Serve a static file by name.
 * @param {string} rawName  — untrusted filename from user input
 */
function serveFile(rawName, res) {
  // Step 1: strip all directory components — traversal impossible after this
  const safeName = path.basename(rawName);

  // Step 2: enforce extension allowlist
  const ext = path.extname(safeName).toLowerCase();
  if (!ALLOWED_EXTS.has(ext)) {
    res.status(404).send('Not found');
    return;
  }

  // Step 3: construct the final path — basename guarantees no traversal
  const filePath = path.join(STATIC_DIR, safeName);

  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) { res.status(404).send('Not found'); return; }
    res.send(data);
  });
}

// Simulate Express-like usage
const mockRes = {
  status(code) { console.log('Status:', code); return this; },
  send(body) { console.log('Response:', String(body).slice(0, 80)); },
};

serveFile('../../etc/passwd', mockRes);    // blocked — no .txt/.json ext
serveFile('../secret.json', mockRes);      // safe — becomes 'secret.json' in STATIC_DIR
serveFile('data.txt', mockRes);            // normal usage
